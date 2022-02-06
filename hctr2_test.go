package hctr2

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/exp/rand"
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
			c, err := NewAES(unhex(v.Input.Key))
			if err != nil {
				t.Fatal(err)
			}
			plaintext := unhex(v.Plaintext)
			tweak := unhex(v.Input.Tweak)
			got := make([]byte, len(plaintext))

			want := unhex(v.Ciphertext)
			c.Encrypt(got, plaintext, tweak)
			if !bytes.Equal(got, want) {
				t.Fatalf("#%d: (%s): expected %x, got %x",
					i, v.Description, want, got)
			}
			c.Decrypt(got, want, tweak)
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("#%d: (%s): expected %x, got %x",
					i, v.Description, plaintext, got)
			}
		}
	}

	for _, s := range []string{
		"HCTR2_AES256",
		"HCTR2_AES192",
		"HCTR2_AES128",
	} {
		t.Run(s, func(t *testing.T) {
			test(t, filepath.Join("testdata", s+".json"))
		})
	}
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
			c, err := NewAES(unhex(v.Input.Key))
			if err != nil {
				t.Fatal(err)
			}
			nonce := unhex(v.Input.Nonce)
			src := unhex(v.Plaintext)
			got := make([]byte, len(src))
			want := unhex(v.Ciphertext)

			c.xctr(got, src, (*[BlockSize]byte)(nonce))
			if !bytes.Equal(got, want) {
				t.Fatalf("#%d: (%s): expected %x, got %x",
					i, v.Description, want, got)
			}
		}
	}

	for _, s := range []string{
		"XCTR_AES256",
		"XCTR_AES192",
		"XCTR_AES128",
	} {
		t.Run(s, func(t *testing.T) {
			test(t, filepath.Join("testdata", s+".json"))
		})
	}
}

func TestSelfFuzz(t *testing.T) {
	for _, n := range []int{16, 24, 32} {
		name := fmt.Sprintf("AES-%d", n*8)
		t.Run(name, func(t *testing.T) {
			key := make([]byte, n)
			c, err := NewAES(key)
			if err != nil {
				t.Fatal(err)
			}
			testSelfFuzz(t, c)
		})
	}
}

func testSelfFuzz(t *testing.T, c *Cipher) {
	seed := uint64(time.Now().UnixNano())
	rng := rand.New(rand.NewSource(seed))
	d := 2 * time.Second
	if testing.Short() {
		d = 10 * time.Millisecond
	}
	timer := time.NewTimer(d)

	const (
		N = BlockSize * 2
	)
	buf := make([]byte, N)
	for i := range buf {
		buf[i] = byte(i)
	}
	tweak := make([]byte, N)
	for i := range tweak {
		tweak[i] = byte(i)
	}
	for {
		select {
		case <-timer.C:
			return
		default:
		}

		n := rng.Intn(len(buf)-(BlockSize+1)) + (BlockSize + 1)
		m := rng.Intn(n-BlockSize) + BlockSize
		w := rng.Intn(len(tweak))
		c.Encrypt(buf[:n], buf[:m], tweak[:w])
		c.Decrypt(buf[:n], buf[:m], tweak[:w])
		for i, c := range buf[:m] {
			if c != byte(i) {
				t.Fatalf("expected %x, got %x", byte(i), c)
			}
		}
	}
}

var sink []byte

func BenchmarkEncryptAES256_512(b *testing.B) {
	benchmarkEncrypt(b, 32, 512)
}

func BenchmarkEncryptAES256_4096(b *testing.B) {
	benchmarkEncrypt(b, 32, 4096)
}

func BenchmarkEncryptAES256_8192(b *testing.B) {
	benchmarkEncrypt(b, 32, 8192)
}

func benchmarkEncrypt(b *testing.B, keyLen, bufLen int) {
	key := make([]byte, keyLen)
	c, _ := NewAES(key)
	buf := make([]byte, bufLen)
	tweak := make([]byte, 16)

	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(tweak[0:8], uint64(i))
		c.Encrypt(buf, buf, tweak)
	}
	sink = buf
}
