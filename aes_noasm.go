//go:build !arm64 || !gc || purego

package hctr2

import (
	"crypto/aes"
	"crypto/cipher"
)

func newCipher(key []byte) cipher.Block {
	// len(key) is checked by NewAES.
	block, _ := aes.NewCipher(key)
	return block
}
