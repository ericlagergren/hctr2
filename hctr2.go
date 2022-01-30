// Package HCTR2 implements the HCTR2 length-preserving
// encryption algorithm.
//
// [0]: https://eprint.iacr.org/2021/1441
package hctr2

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/ericlagergren/hctr2/internal/subtle"
	"github.com/ericlagergren/polyval"
)

func NewCipher(block cipher.Block) *Cipher {
	return &Cipher{
		block: block,
	}
}

type Cipher struct {
	block cipher.Block
}

func (c *Cipher) Encrypt(ciphertext, plaintext, tweak []byte) {
	blockSize := c.block.BlockSize()

	if len(ciphertext) < len(plaintext) {
		panic("hctr2: ciphertext is smaller than plaintext")
	}
	// if len(plaintext)%blockSize != 0 {
	// 	println(len(plaintext), blockSize)
	// 	panic("hctr2: plaintext is not a multiple of the block size")
	// }
	if subtle.InexactOverlap(ciphertext[:len(plaintext)], plaintext) {
		panic("hctr2: invalid buffer overlap")
	}

	// h ← Ek(bin(0))
	h := make([]byte, blockSize)
	c.block.Encrypt(h, h)

	// L ← Ek(bin(1))
	L := make([]byte, blockSize)
	L[0] = 1
	c.block.Encrypt(L, L)

	// M || N ← P, |M| = n
	M := plaintext[0:blockSize]
	N := plaintext[blockSize:]

	// MM ← M ⊕ H_h(T, N)
	MM := xor(M, c.polyhash(h, tweak, N))

	// UU ← Ek(MM)
	UU := make([]byte, len(MM))
	c.block.Encrypt(UU, MM)

	// S ← MM ⊕ UU ⊕ L
	S := xor(MM, UU)
	S = xor(S, L)

	// V ← N ⊕ XCTR_k(S)[0;|N|]
	V := xor(N, c.xctr(S, N))

	// U ← UU ⊕ Hh(T, V)
	U := xor(UU, c.polyhash(h, tweak, V))

	// C ← U || V
	n := copy(ciphertext, U)
	copy(ciphertext[n:], V)
}

func (c *Cipher) xctr(nonce, plaintext []byte) []byte {
	var res []byte
	for i := 1; len(res) < len(plaintext); i++ {
		count := make([]byte, len(nonce))
		binary.LittleEndian.PutUint64(count[0:8], uint64(i))
		v := xor(nonce, count)
		c.block.Encrypt(v, v)
		res = append(res, v...)
	}
	return xor(plaintext, res[:len(plaintext)])
}

func (c *Cipher) polyhash(h, tweak, M []byte) []byte {
	blockSize := c.block.BlockSize()

	// TODO(eric): assumes len(h) == 16
	p, err := polyval.New(h)
	if err != nil {
		panic(err)
	}

	// If n divides |M|:
	//    POLYVAL(h, bin(2*|T| + 2) || pad(T) || M)
	// else:
	//    POLYVAL(h, bin(2*|T| + 3) || pad(T) || pad(M || 1))
	blocks := make([]byte, blockSize)

	l := len(tweak)*8*2 + 2
	if len(M)%blockSize != 0 {
		l++
	}
	binary.LittleEndian.PutUint64(blocks, uint64(l))
	blocks = append(blocks, tweak...)
	for len(blocks)%blockSize != 0 {
		blocks = append(blocks, 0)
	}
	blocks = append(blocks, M...)
	if len(M)%blockSize != 0 {
		blocks = append(blocks, 1)
	}
	for len(blocks)%blockSize != 0 {
		blocks = append(blocks, 0)
	}

	for len(blocks) > 0 {
		// TODO(eric): this assumes blockSize == 16
		p.Update(blocks[0:16])
		blocks = blocks[16:]
	}
	return p.Sum(nil)
}

func xor(x, y []byte) []byte {
	z := make([]byte, len(x))
	for i := range x {
		z[i] = x[i] ^ y[i]
	}
	return z
}
