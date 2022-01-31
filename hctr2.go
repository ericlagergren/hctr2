// Package HCTR2 implements the HCTR2 length-preserving
// encryption algorithm.
//
// [0]: https://eprint.iacr.org/2021/1441
package hctr2

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/ericlagergren/hctr2/internal/subtle"
	"github.com/ericlagergren/polyval"
)

// BlockSize is the size of block allowed by this package.
const BlockSize = 16

// NewCipher creates a HCTR2 cipher.
//
// The provided Block must have a block size of exactly
// BlockSize. This restriction may be lifted in the future.
func NewCipher(block cipher.Block) (*Cipher, error) {
	if n := block.BlockSize(); n != BlockSize {
		return nil, fmt.Errorf("hctr2: invalid block size: %d", n)
	}
	return &Cipher{
		block: block,
	}, nil
}

// Cipher is an HCTR2 cipher.
//
// TODO(eric): docs
type Cipher struct {
	block cipher.Block
}

// Encrypt encrypts plaintext with tweak and writes the result to
// ciphertext.
//
// plaintext must be at least one block long.
//
// The length of ciphertext must be greater than or equal to the
// length of plaintext.
//
// ciphertext and plaintext must overlap entirely or not at all.
func (c *Cipher) Encrypt(ciphertext, plaintext, tweak []byte) {
	if len(ciphertext) < len(plaintext) {
		panic("hctr2: ciphertext is smaller than plaintext")
	}
	if len(plaintext) < BlockSize {
		panic("hctr2: plaintext is not a smaller than the block size")
	}
	if subtle.InexactOverlap(ciphertext[:len(plaintext)], plaintext) {
		panic("hctr2: invalid buffer overlap")
	}

	// M || N ← P, |M| = n
	M := plaintext[:BlockSize]
	N := plaintext[BlockSize:]

	// h ← Ek(bin(0))
	h := make([]byte, BlockSize)
	c.block.Encrypt(h, h)

	p, err := polyval.New(h)
	if err != nil {
		panic(err)
	}
	initTweak(p, tweak, len(N))
	// Save the POLYVAL state after adding the tweak since we can
	// reuse it later.
	state, _ := p.MarshalBinary()

	// MM ← M ⊕ H_h(T, N)
	MM := c.polyhash(p, N)
	xorBlock(MM, M, MM)

	// UU ← Ek(MM)
	UU := make([]byte, BlockSize)
	c.block.Encrypt(UU, MM)

	// L ← Ek(bin(1))
	L := make([]byte, BlockSize)
	binary.LittleEndian.PutUint64(L[0:8], 1)
	c.block.Encrypt(L, L)

	// S ← MM ⊕ UU ⊕ L
	S := make([]byte, len(MM))
	xorBlock3(S, MM, UU, L)

	// V ← N ⊕ XCTR_k(S)[0;|N|]
	V := ciphertext[BlockSize:]
	c.xctr(V, N, S)

	err = p.UnmarshalBinary(state)
	if err != nil {
		panic(err)
	}

	// U ← UU ⊕ Hh(T, V)
	U := ciphertext
	xorBlock(U, UU, c.polyhash(p, V))

	// C ← U || V
	// U = ciphertext[:BlockSize]
	// V = ciphertext[BlockSize:]
}

func initTweak(h *polyval.Polyval, tweak []byte, n int) {
	// M = the input to the hash.
	// n = the block size of the hash.
	//
	// If n divides |M|:
	//    POLYVAL(h, bin(2*|T| + 2) || pad(T) || M)
	// else:
	//    POLYVAL(h, bin(2*|T| + 3) || pad(T) || pad(M || 1))
	block := make([]byte, BlockSize)
	l := len(tweak)*8*2 + 2
	if n%BlockSize != 0 {
		l++
	}
	binary.LittleEndian.PutUint64(block, uint64(l))
	h.Update(block)

	for len(tweak) >= BlockSize {
		h.Update(tweak[0:BlockSize])
		tweak = tweak[BlockSize:]
	}
	if len(tweak) > 0 {
		for i := range block {
			block[i] = 0
		}
		copy(block, tweak)
		h.Update(block)
	}
}

func (c *Cipher) polyhash(h *polyval.Polyval, M []byte) []byte {
	for len(M) >= BlockSize {
		h.Update(M[0:BlockSize])
		M = M[BlockSize:]
	}
	if len(M) > 0 {
		block := make([]byte, BlockSize)
		n := copy(block, M)
		block[n] = 1
		h.Update(block)
	}
	return h.Sum(nil)
}

// xctr performs XCTR_k(S) ^ nonce.
func (c *Cipher) xctr(dst, src, nonce []byte) {
	if len(nonce) == 0 {
		return
	}

	// TODO(eric): we might be able to get rid of this variable
	// if len(dst) % BlockSize == 0.
	block := make([]byte, BlockSize)

	i := 0
	nblocks := len(src) / BlockSize
	for i < nblocks {
		binary.LittleEndian.PutUint64(block[0:8], uint64(i+1))
		binary.LittleEndian.PutUint64(block[8:16], 0)

		xorBlock(block, block, nonce)
		c.block.Encrypt(block, block)
		xorBlock(dst, block, src)

		dst = dst[BlockSize:]
		src = src[BlockSize:]
		i++
	}

	if len(src) != 0 {
		binary.LittleEndian.PutUint64(block[0:8], uint64(i+1))
		binary.LittleEndian.PutUint64(block[8:16], 0)

		xor(block, block, nonce, BlockSize)
		c.block.Encrypt(block, block)
		xor(dst, block, src, len(src))
	}
}

// xorBlocks sets z = x^y.
func xorBlock(z, x, y []byte) {
	x0 := binary.LittleEndian.Uint64(x[0:8])
	x1 := binary.LittleEndian.Uint64(x[8:16])
	y0 := binary.LittleEndian.Uint64(y[0:8])
	y1 := binary.LittleEndian.Uint64(y[8:16])
	binary.LittleEndian.PutUint64(z[0:8], x0^y0)
	binary.LittleEndian.PutUint64(z[8:16], x1^y1)
}

// xorBlock3 sets z = v^x^y.
func xorBlock3(z, v, x, y []byte) {
	v0 := binary.LittleEndian.Uint64(v[0:8])
	v1 := binary.LittleEndian.Uint64(v[8:16])
	x0 := binary.LittleEndian.Uint64(x[0:8])
	x1 := binary.LittleEndian.Uint64(x[8:16])
	y0 := binary.LittleEndian.Uint64(y[0:8])
	y1 := binary.LittleEndian.Uint64(y[8:16])
	binary.LittleEndian.PutUint64(z[0:8], v0^x0^y0)
	binary.LittleEndian.PutUint64(z[8:16], v1^x1^y1)
}

// xor sets z = x^y for up to n bytes.
func xor(z, x, y []byte, n int) {
	_ = z[n-1]
	for i := 0; i < n; i++ {
		z[i] = x[i] ^ y[i]
	}
}
