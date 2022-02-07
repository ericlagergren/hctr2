//go:build !(amd64 || arm64) || !gc || purego

package hctr2

import (
	"crypto/aes"
	"crypto/cipher"
)

func newCipher(key []byte) cipher.Block {
	block, err := aes.NewCipher(key)
	if err != nil {
		// len(key) is checked by NewAES.
		panic(err)
	}
	return block
}
