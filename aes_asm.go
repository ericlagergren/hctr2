// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (amd64 || arm64) && gc && !purego

package hctr2

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/ericlagergren/subtle"
)

//go:noescape
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func decryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func expandKeyAsm(nr int, key *byte, enc, dec *uint32)

type aesCipher struct {
	nr  int
	enc [32 + 28]uint32
	dec [32 + 28]uint32
}

var (
	_ cipher.Block = (*aesCipher)(nil)
	_ xctrAble     = (*aesCipher)(nil)
)

func newCipher(key []byte) cipher.Block {
	if !haveAsm {
		block, err := aes.NewCipher(key)
		if err != nil {
			// len(key) is checked by NewAES.
			panic(err)
		}
		return block
	}
	c := aesCipher{
		nr: 6 + len(key)/4,
	}
	expandKeyAsm(6+len(key)/4, &key[0], &c.enc[0], &c.dec[0])
	return &c
}

func (*aesCipher) BlockSize() int {
	return BlockSize
}

func (c *aesCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("hctr2: input not full block")
	}
	if len(dst) < BlockSize {
		panic("hctr2: output not full block")
	}
	if subtle.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("hctr2: invalid buffer overlap")
	}
	encryptBlockAsm(c.nr, &c.enc[0], &dst[0], &src[0])
}

func (c *aesCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("hctr2: input not full block")
	}
	if len(dst) < BlockSize {
		panic("hctr2: output not full block")
	}
	if subtle.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("hctr2: invalid buffer overlap")
	}
	decryptBlockAsm(c.nr, &c.dec[0], &dst[0], &src[0])
}

func (c *aesCipher) xctr(dst, src []byte, nonce *[BlockSize]byte) {
	n := len(src) / BlockSize
	if n > 0 {
		xctrAsm(c.nr, &c.enc[0], &dst[0], &src[0], n, nonce)
		src = src[n*BlockSize:]
		dst = dst[n*BlockSize:]
	}
	if len(src) > 0 {
		var ctr [BlockSize]byte
		binary.LittleEndian.PutUint64(ctr[0:8], uint64(n+1))
		binary.LittleEndian.PutUint64(ctr[8:16], 0)

		xorBlock(&ctr, &ctr, nonce)
		encryptBlockAsm(c.nr, &c.enc[0], &ctr[0], &ctr[0])
		xor(dst, ctr[:], src, len(src))
	}
}
