package hctr2

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func unhex(s string) []byte {
	p, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return p
}

type vector struct {
	Cipher struct {
		Cipher      string `json:"cipher"`
		BlockCipher struct {
			Cipher  string `json:"cipher"`
			Lengths struct {
				Block int `json:"block"`
				Key   int `json:"key"`
				Nonce int `json:"nonce"`
			} `json:"lengths"`
		} `json:"block_cipher"`
	} `json:"cipher"`
	Description string `json:"description"`
	Input       struct {
		Key     string `json:"key_hex"`
		Tweak   string `json:"tweak_hex"`
		Message string `json:"message_hex"`
		Nonce   string `json:"nonce_hex"`
	} `json:"input"`
	Plaintext  string `json:"plaintext_hex"`
	Ciphertext string `json:"ciphertext_hex"`
	Hash       string `json:"hash_hex"`
}

func TestHCTR2Vectors(t *testing.T) {
	test := func(t *testing.T, path string) {
		var vecs []vector
		buf, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		err = json.Unmarshal(buf, &vecs)
		if err != nil {
			t.Fatal(err)
		}
		for i, v := range vecs {
			block, err := aes.NewCipher(unhex(v.Input.Key))
			if err != nil {
				t.Fatal(err)
			}
			c := NewCipher(block)
			plaintext := unhex(v.Plaintext)
			got := make([]byte, len(plaintext))
			c.Encrypt(got, plaintext, unhex(v.Input.Tweak))
			want := unhex(v.Ciphertext)
			if !bytes.Equal(got, want) {
				t.Fatalf("#%d: (%s): expected %x, got %x",
					i, v.Description, want, got)
			}
		}
	}

	t.Run("AES-256", func(t *testing.T) {
		test(t, filepath.Join("testdata", "hctr2_aes256.json"))
	})
}

func TestXCTRVectors(t *testing.T) {
	test := func(t *testing.T, path string) {
		var vecs []vector
		buf, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		err = json.Unmarshal(buf, &vecs)
		if err != nil {
			t.Fatal(err)
		}
		for i, v := range vecs {
			block, err := aes.NewCipher(unhex(v.Input.Key))
			if err != nil {
				t.Fatal(err)
			}
			c := NewCipher(block)
			nonce := unhex(v.Input.Nonce)
			plaintext := unhex(v.Plaintext)
			got := c.xctr(nonce, plaintext)
			want := unhex(v.Ciphertext)
			if !bytes.Equal(got, want) {
				t.Fatalf("#%d: (%s): expected %x, got %x",
					i, v.Description, want, got)
			}
		}
	}

	t.Run("AES-256", func(t *testing.T) {
		test(t, filepath.Join("testdata", "xctr_aes256.json"))
	})
}
