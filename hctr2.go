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

	c := &Cipher{
		block: block,
	}

	// L ← Ek(bin(1))
	binary.LittleEndian.PutUint64(c.L[0:8], 1)
	block.Encrypt(c.L[:], c.L[:])

	// h ← Ek(bin(0))
	h := make([]byte, BlockSize)
	block.Encrypt(h, h)

	p, err := polyval.New(h)
	if err != nil {
		return nil, err
	}
	c.h = p
	return c, nil
}

// Cipher is an HCTR2 cipher.
//
// TODO(eric): docs
type Cipher struct {
	block cipher.Block
	h     *polyval.Polyval
	L     [BlockSize]byte
	sum   [BlockSize]byte
	s     [BlockSize]byte
	uu    [BlockSize]byte
	mm    [BlockSize]byte
	ctr   [BlockSize]byte
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
		panic("hctr2: plaintext is smaller than the block size")
	}
	if subtle.InexactOverlap(ciphertext[:len(plaintext)], plaintext) {
		panic("hctr2: invalid buffer overlap")
	}
	c.hctr2(c.block.Encrypt, ciphertext, plaintext, tweak)
}

// Decrypt decrypts ciphertext with tweak and writes the result
// to plaintext.
//
// The length of plaintext must be greater than or equal to the
// length of plaintext.
//
// plaintext and ciphertext must overlap entirely or not at all.
func (c *Cipher) Decrypt(plaintext, ciphertext, tweak []byte) {
	if len(plaintext) < len(ciphertext) {
		panic("hctr2: plaintext is smaller than ciphertext")
	}
	if len(ciphertext) < BlockSize {
		panic("hctr2: ciphertext is smaller than the block size")
	}
	if subtle.InexactOverlap(plaintext[:len(ciphertext)], ciphertext) {
		panic("hctr2: invalid buffer overlap")
	}
	c.hctr2(c.block.Decrypt, plaintext, ciphertext, tweak)
}

func (c *Cipher) hctr2(crypt func(dst, src []byte), dst, src, tweak []byte) {
	// M || N ← P, |M| = n
	M := src[:BlockSize]
	N := src[BlockSize:]

	c.initTweak(tweak, len(N))
	// Save the POLYVAL state after adding the tweak since we can
	// reuse it later.
	state, _ := c.h.MarshalBinary()

	// MM ← M ⊕ H_h(T, N)
	c.polyhash(c.sum[:0], N)
	xorBlock(c.mm[:], M, c.sum[:])

	// UU ← Ek(MM)
	crypt(c.uu[:], c.mm[:])

	// S ← MM ⊕ UU ⊕ L
	xorBlock3(c.s[:], c.mm[:], c.uu[:], c.L[:])

	// V ← N ⊕ XCTR_k(S)[0;|N|]
	V := dst[BlockSize:]
	c.xctr(crypt, V, N, c.s[:])

	err := c.h.UnmarshalBinary(state)
	if err != nil {
		panic(err)
	}

	// U ← UU ⊕ Hh(T, V)
	c.polyhash(c.sum[:0], V)
	xorBlock(dst, c.uu[:], c.sum[:])
}

func (c *Cipher) initTweak(tweak []byte, n int) {
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
	c.h.Update(block)

	for len(tweak) >= BlockSize {
		c.h.Update(tweak[0:BlockSize])
		tweak = tweak[BlockSize:]
	}
	if len(tweak) > 0 {
		for i := range block {
			block[i] = 0
		}
		copy(block, tweak)
		c.h.Update(block)
	}
}

func (c *Cipher) polyhash(dst, src []byte) {
	if len(src) >= BlockSize {
		n := len(src) &^ (BlockSize - 1)
		c.h.Update(src[:n])
		src = src[n:]
	}
	if len(src) > 0 {
		block := make([]byte, BlockSize)
		n := copy(block, src)
		block[n] = 1
		c.h.Update(block)
	}
	c.h.Sum(dst)
}

// xctr performs XCTR_k(S) ^ nonce.
func (c *Cipher) xctr(crypt func(dst, src []byte), dst, src, nonce []byte) {
	if len(nonce) == 0 {
		return
	}

	i := 0
	nblocks := len(src) / BlockSize
	for i < nblocks {
		binary.LittleEndian.PutUint64(c.ctr[0:8], uint64(i+1))
		binary.LittleEndian.PutUint64(c.ctr[8:16], 0)

		xorBlock(c.ctr[:], c.ctr[:], nonce)
		crypt(c.ctr[:], c.ctr[:])
		xorBlock(dst, c.ctr[:], src)

		dst = dst[BlockSize:]
		src = src[BlockSize:]
		i++
	}

	if len(src) != 0 {
		binary.LittleEndian.PutUint64(c.ctr[0:8], uint64(i+1))
		binary.LittleEndian.PutUint64(c.ctr[8:16], 0)

		xor(c.ctr[:], c.ctr[:], nonce, BlockSize)
		crypt(c.ctr[:], c.ctr[:])
		xor(dst, c.ctr[:], src, len(src))
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
	// This is not written in the obvious manner so that the
	// compiler will inline it.

	z0 := binary.LittleEndian.Uint64(v[0:]) ^
		binary.LittleEndian.Uint64(x[0:]) ^
		binary.LittleEndian.Uint64(y[0:])
	binary.LittleEndian.PutUint64(z[0:], z0)

	z1 := binary.LittleEndian.Uint64(v[8:]) ^
		binary.LittleEndian.Uint64(x[8:]) ^
		binary.LittleEndian.Uint64(y[8:])
	binary.LittleEndian.PutUint64(z[8:], z1)
}

// xor sets z = x^y for up to n bytes.
func xor(z, x, y []byte, n int) {
	_ = z[n-1]
	for i := 0; i < n; i++ {
		z[i] = x[i] ^ y[i]
	}
}
