// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (amd64 || arm64) && gc && !purego

package hctr2

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"runtime"

	"github.com/ericlagergren/hctr2/internal/subtle"
	"golang.org/x/sys/cpu"
)

//go:noescape
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func decryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func expandKeyAsm(nr int, key *byte, enc *uint32, dec *uint32)

type aesCipher struct {
	enc []uint32
	dec []uint32
}

var (
	_ cipher.Block = (*aesCipher)(nil)
	_ xctrAble     = (*aesCipher)(nil)
)

var haveAES = runtime.GOOS == "darwin" ||
	cpu.ARM64.HasAES ||
	cpu.X86.HasAES

func newCipher(key []byte) cipher.Block {
	if !haveAES {
		block, err := aes.NewCipher(key)
		if err != nil {
			// len(key) is checked by NewAES.
			panic(err)
		}
		return block
	}
	n := len(key) + 28
	c := aesCipher{
		enc: make([]uint32, n),
		dec: make([]uint32, n),
	}
	expandKeyAsm(6+len(key)/4, &key[0], &c.enc[0], &c.dec[0])
	return &c
}

func (c *aesCipher) BlockSize() int { return BlockSize }

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
	encryptBlockAsm(len(c.enc)/4-1, &c.enc[0], &dst[0], &src[0])
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
	decryptBlockAsm(len(c.dec)/4-1, &c.dec[0], &dst[0], &src[0])
}

func (c *aesCipher) xctr(dst, src []byte, nonce *[BlockSize]byte) {
	n := len(src) / BlockSize
	if true {
		if n > 0 {
			xctrAsm(len(c.enc)/4-1, &c.enc[0], &dst[0], &src[0], n, nonce)
			src = src[n*BlockSize:]
			dst = dst[n*BlockSize:]
		}
	} else {
		n = 0
		for len(src) >= BlockSize && len(dst) >= BlockSize {
			n++
			var ctr [BlockSize]byte
			binary.LittleEndian.PutUint64(ctr[0:8], uint64(n))
			binary.LittleEndian.PutUint64(ctr[8:16], 0)

			xorBlock(&ctr, &ctr, nonce)
			encryptBlockAsm(len(c.enc)/4-1, &c.enc[0], &ctr[0], &ctr[0])
			xorBlock((*[BlockSize]byte)(dst), &ctr, (*[BlockSize]byte)(src))

			dst = dst[BlockSize:]
			src = src[BlockSize:]
		}
	}
	if len(src) > 0 {
		var ctr [BlockSize]byte
		binary.LittleEndian.PutUint64(ctr[0:8], uint64(n+1))
		binary.LittleEndian.PutUint64(ctr[8:16], 0)

		xorBlock(&ctr, &ctr, nonce)
		encryptBlockAsm(len(c.enc)/4-1, &c.enc[0], &ctr[0], &ctr[0])
		xor(dst, ctr[:], src, len(src))
	}
}
