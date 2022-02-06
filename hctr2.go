// Package HCTR2 implements the HCTR2 length-preserving
// encryption algorithm.
//
// HCTR2 is designed for situations where the length of the
// ciphertext must exactly match the length of the plaintext,
// like disk encryption.
//
// This implementation uses a hardware-accelerated POLYVAL
// implementation when possible; the block cipher is left to the
// caller. The recommended block cipher is AES.
//
// [hctr2]: https://eprint.iacr.org/2021/1441
package hctr2

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/ericlagergren/hctr2/internal/subtle"
	"github.com/ericlagergren/polyval"
)

// BlockSize is the size of block allowed by this package.
const BlockSize = 16

// New creates a HCTR2 cipher.
//
// The provided Block must have a block size of exactly
// BlockSize. This restriction may be lifted in the future.
//
// The recommended block cipher is AES.
func New(block cipher.Block) (*Cipher, error) {
	if n := block.BlockSize(); n != BlockSize {
		return nil, fmt.Errorf("hctr2: invalid block size: %d", n)
	}

	// h ← Ek(bin(0))
	h := make([]byte, BlockSize)
	block.Encrypt(h, h)

	p, err := polyval.New(h)
	if err != nil {
		return nil, err
	}

	c := &Cipher{
		block: block,
		h:     p,
	}
	// L ← Ek(bin(1))
	binary.LittleEndian.PutUint64(c.l[0:8], 1)
	block.Encrypt(c.l[:], c.l[:])

	return c, nil
}

// NewAES creates a HCTR2 cipher using AES.
//
// If supported, the returned Cipher will use a hardware XCTR
// implementation. Otherwise, it defers to crypto/aes.
//
// The provided AES key should be either 16, 24, or 32 bytes to
// choose AES-128, AES-192, or AES-256, respectively.
func NewAES(key []byte) (*Cipher, error) {
	switch len(key) {
	case 16, 24, 32:
		// OK
	default:
		return nil, aes.KeySizeError(len(key))
	}
	return New(newCipher(key))
}

// Cipher is an instance of the HCTR2 cipher.
type Cipher struct {
	// block is the underlying block cipher.
	block cipher.Block
	// h is the running POLYVAL.
	h *polyval.Polyval
	// sum contains the output from the most recent call to
	// polyhash.
	sum [BlockSize]byte
	// l is E_k(bin(1)).
	//
	// It is XORed with mm and uu to create s.
	l [BlockSize]byte
	// s is the nonce XORed with each block in XCTR.
	s [BlockSize]byte
	// uu is E_k(mm).
	//
	// It is XORed with uu and l to create s.
	uu [BlockSize]byte
	// mm is the first plainext block XORed with the output of
	// polyhash(tweak).
	mm [BlockSize]byte
	// ctr is the counter block used by XCTR to create the
	// ciphertext.
	ctr [BlockSize]byte
	// tweakLen is the length of the most recent call to
	// initTweak.
	tweakLen int
	// state0 and state1 are the two possible initial states to
	// polyhash.
	//
	// They are derived the first time initTweak is called either
	// the states are not cached or the tweak length has changed.
	//
	// state0 is the case where the length of the plaintext is
	// evenly divisible by the block size.
	//
	// state1 is the case where the length of the plaintext is
	// not evenly divisible by the block size.
	state0, state1 []byte
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
	c.hctr2(ciphertext, plaintext, tweak, true)
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
	c.hctr2(plaintext, ciphertext, tweak, false)
}

func (c *Cipher) hctr2(dst, src, tweak []byte, seal bool) {
	// Assert that we have at least one block.
	_ = dst[BlockSize-1]
	_ = src[BlockSize-1]

	// M || N ← P, |M| = n
	M := src[:BlockSize]
	N := src[BlockSize:]

	c.initTweak(tweak, len(N))
	// Save the POLYVAL state after adding the tweak since we can
	// reuse it across both calls to polyhash.
	state, _ := c.h.MarshalBinary()

	// MM ← M ⊕ H_h(T, N)
	xorBlock(&c.mm, (*[BlockSize]byte)(M), c.polyhash(N))

	// UU ← Ek(MM)
	if seal {
		c.block.Encrypt(c.uu[:], c.mm[:])
	} else {
		c.block.Decrypt(c.uu[:], c.mm[:])
	}

	// S ← MM ⊕ UU ⊕ L
	xorBlock3(&c.s, &c.mm, &c.uu, &c.l)

	// V ← N ⊕ XCTR_k(S)[0;|N|]
	V := dst[BlockSize:]
	c.xctr(V, N, &c.s)

	c.h.UnmarshalBinary(state)

	// U ← UU ⊕ Hh(T, V)
	xorBlock((*[BlockSize]byte)(dst), &c.uu, c.polyhash(V))
}

func (c *Cipher) initTweak(tweak []byte, n int) {
	// The first block in the hash of the tweak is the same so
	// long as the length of the tweak is the same, so cache it.
	if c.state0 == nil || c.tweakLen != len(tweak) {
		// M = the input to the hash.
		// n = the block size of the hash.
		//
		// If n divides |M|:
		//    POLYVAL(h, bin(2*|T| + 2) || pad(T) || M)
		// else:
		//    POLYVAL(h, bin(2*|T| + 3) || pad(T) || pad(M || 1))
		l := uint64(len(tweak)*8*2 + 2)
		block := make([]byte, BlockSize)

		binary.LittleEndian.PutUint64(block, l)
		c.h.Update(block)
		c.state0, _ = c.h.MarshalBinary()
		c.h.Reset()

		binary.LittleEndian.PutUint64(block, l+1)
		c.h.Update(block)
		c.state1, _ = c.h.MarshalBinary()
		c.h.Reset()

		c.tweakLen = len(tweak)
	}

	if n%BlockSize == 0 {
		c.h.UnmarshalBinary(c.state0)
	} else {
		c.h.UnmarshalBinary(c.state1)
	}

	if len(tweak) >= BlockSize {
		n := len(tweak) &^ (BlockSize - 1)
		c.h.Update(tweak[:n])
		tweak = tweak[n:]
	}
	if len(tweak) > 0 {
		block := make([]byte, BlockSize)
		copy(block, tweak)
		c.h.Update(block)
	}
}

// polyhash computes H_h(tweak, src) and writes the digest to
// c.sum.
//
// For convenience, polyhash returns a pointer to c.sum.
func (c *Cipher) polyhash(src []byte) *[BlockSize]byte {
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
	c.h.Sum(c.sum[:0])
	return &c.sum
}

// xctr performs XCTR_k(S) ^ nonce.
func (c *Cipher) xctr(dst, src []byte, nonce *[BlockSize]byte) {
	if v, ok := c.block.(xctrAble); ok {
		v.xctr(dst, src, nonce)
		return
	}

	i := 1
	for len(src) >= BlockSize && len(dst) >= BlockSize {
		binary.LittleEndian.PutUint64(c.ctr[0:8], uint64(i))
		binary.LittleEndian.PutUint64(c.ctr[8:16], 0)

		xorBlock(&c.ctr, &c.ctr, nonce)
		c.block.Encrypt(c.ctr[:], c.ctr[:])
		xorBlock((*[BlockSize]byte)(dst), &c.ctr, (*[BlockSize]byte)(src))

		dst = dst[BlockSize:]
		src = src[BlockSize:]
		i++
	}

	if len(src) > 0 {
		ctr := c.ctr[:]
		binary.LittleEndian.PutUint64(ctr[0:8], uint64(i))
		binary.LittleEndian.PutUint64(ctr[8:16], 0)

		xor(ctr, ctr, nonce[:], BlockSize)
		c.block.Encrypt(ctr, ctr)
		xor(dst, ctr, src, len(src))
	}
}

type xctrAble interface {
	xctr(dst, src []byte, nonce *[BlockSize]byte)
}

// xorBlocks sets z = x^y.
func xorBlock(z, x, y *[BlockSize]byte) {
	x0 := binary.LittleEndian.Uint64(x[0:])
	x1 := binary.LittleEndian.Uint64(x[8:])
	y0 := binary.LittleEndian.Uint64(y[0:])
	y1 := binary.LittleEndian.Uint64(y[8:])
	binary.LittleEndian.PutUint64(z[0:], x0^y0)
	binary.LittleEndian.PutUint64(z[8:], x1^y1)
}

// xorBlock3 sets z = v^x^y.
func xorBlock3(z, v, x, y *[BlockSize]byte) {
	// This is written in a non-obvious manner to so that the
	// compiler will inline it starting with Go 1.18.
	z1 := binary.LittleEndian.Uint64(v[8:16]) ^
		binary.LittleEndian.Uint64(x[8:16]) ^
		binary.LittleEndian.Uint64(y[8:16])
	binary.LittleEndian.PutUint64(z[8:16], z1)
	z0 := binary.LittleEndian.Uint64(v[0:8]) ^
		binary.LittleEndian.Uint64(x[0:8]) ^
		binary.LittleEndian.Uint64(y[0:8])
	binary.LittleEndian.PutUint64(z[0:8], z0)
}

// xor sets z = x^y for up to n bytes.
func xor(z, x, y []byte, n int) {
	// This loop condition prevents needless bounds checks.
	for i := 0; i < n && i < len(z) && i < len(x) && i < len(y); i++ {
		z[i] = x[i] ^ y[i]
	}
}
