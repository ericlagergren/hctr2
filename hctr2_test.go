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

var testKeySizes = []int{16, 24, 32}

func randbuf(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

func dup(p []byte) []byte {
	r := make([]byte, len(p))
	copy(r, p)
	return r
}

func unhex(s string) []byte {
	p, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return p
}

func disableAsm(tb testing.TB) {
	old := haveAsm
	haveAsm = false
	tb.Cleanup(func() {
		haveAsm = old
	})
}

// runTests runs both generic and assembly tests.
func runTests(t *testing.T, fn func(t *testing.T)) {
	if haveAsm {
		t.Run("assembly", func(t *testing.T) {
			t.Helper()
			fn(t)
		})
	}
	t.Run("generic", func(t *testing.T) {
		t.Helper()
		disableAsm(t)
		fn(t)
	})
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

// TestHCTR2Vectors tests Cipher with test vectors from
// github.com/google/hctr2.
func TestHCTR2Vectors(t *testing.T) {
	runTests(t, testHCTR2Vectors)
}

func testHCTR2Vectors(t *testing.T) {
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

// TestXCTRVectors tests Cipher.xctr with test vectors from
// github.com/google/hctr2.
func TestXCTRVectors(t *testing.T) {
	runTests(t, testXCTRVectors)
}

func testXCTRVectors(t *testing.T) {
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

// TestSelfFuzz tests encrypting then decrypting random inputs.
//
// Is a substitute until there is another implementation to test
// against.
func TestSelfFuzz(t *testing.T) {
	test := func(t *testing.T) {
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
	runTests(t, test)
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
		N = (BlockSize * 2) + BlockSize/2
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

// TestOverlap tests Encrypt and Decryptwith overlapping buffers.
func TestOverlap(t *testing.T) {
	test := func(t *testing.T) {
		for _, keyLen := range testKeySizes {
			t.Run(fmt.Sprintf("AES-%d", keyLen*8), func(t *testing.T) {
				testOverlap(t, keyLen)
			})
		}
	}
	runTests(t, test)
}

func testOverlap(t *testing.T, keySize int) {
	// TODO(eric): this was copied from my AES-GCM-SIV tests, so
	// it probably could be simplified.
	args := func() (key, plaintext, tweak []byte) {
		type arg struct {
			buf  []byte
			ptr  *[]byte
			i, j int
		}
		const (
			max = 7789
		)
		args := []arg{
			{buf: randbuf(keySize), ptr: &key},
			{buf: randbuf(rand.Intn(max-BlockSize) + BlockSize), ptr: &plaintext},
			{buf: randbuf(rand.Intn(max)), ptr: &tweak},
		}
		var buf []byte
		for i := range rand.Perm(len(args)) {
			a := &args[i]
			a.i = len(buf)
			buf = append(buf, a.buf...)
			a.j = len(buf)
		}
		buf = buf[:len(buf):len(buf)]
		for i := range args {
			a := &args[i]
			*a.ptr = buf[a.i:a.j:a.j]
		}
		return
	}
	for i := 0; i < 1000; i++ {
		key, plaintext, tweak := args()
		orig := dup(plaintext)

		c, err := NewAES(key)
		if err != nil {
			t.Fatal(err)
		}

		want := make([]byte, len(plaintext))
		c.Encrypt(want, dup(plaintext), dup(tweak))

		got := plaintext
		c.Encrypt(got, plaintext, tweak)
		if !bytes.Equal(want, got) {
			t.Fatalf("expected %x, got %x", want, got)
		}
		c.Decrypt(got, got, tweak)
		if !bytes.Equal(got, orig) {
			t.Fatalf("expected %x, got %x", orig, got)
		}
	}
}

// runBench runs both generic and assembly benchmarks.
func runBench(b *testing.B, fn func(b *testing.B)) {
	if haveAsm {
		b.Run("assembly", func(b *testing.B) {
			b.Helper()
			fn(b)
		})
	}
	b.Run("generic", func(b *testing.B) {
		b.Helper()
		disableAsm(b)
		fn(b)
	})
}

var (
	sink     []byte
	bufSizes = []int{
		512,
		4096,
		8192,
	}
	// benchKeySizes excludes AES-192 because nobody cares about
	// its performance because nobody uses it and it shouldn't
	// exist.
	benchKeySizes = []int{16, 32}
)

func BenchmarkEncrypt(b *testing.B) {
	bench := func(b *testing.B) {
		for _, keyLen := range benchKeySizes {
			for _, bufLen := range bufSizes {
				name := fmt.Sprintf("AES-%d/%d", keyLen*8, bufLen)
				b.Run(name, func(b *testing.B) {
					benchmarkEncrypt(b, keyLen, bufLen)
				})
			}
		}
	}
	runBench(b, bench)
}

func benchmarkEncrypt(b *testing.B, keyLen, bufLen int) {
	b.SetBytes(int64(bufLen))

	key := make([]byte, keyLen)
	c, err := NewAES(key)
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, bufLen)
	tweak := make([]byte, 16)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(tweak[0:8], uint64(i))
		c.Encrypt(buf, buf, tweak)
	}
	sink = buf
}

func BenchmarkDecrypt(b *testing.B) {
	bench := func(b *testing.B) {
		for _, keyLen := range benchKeySizes {
			for _, bufLen := range bufSizes {
				name := fmt.Sprintf("AES-%d/%d", keyLen*8, bufLen)
				b.Run(name, func(b *testing.B) {
					benchmarkDecrypt(b, keyLen, bufLen)
				})
			}
		}
	}
	runBench(b, bench)
}

func benchmarkDecrypt(b *testing.B, keyLen, bufLen int) {
	b.SetBytes(int64(bufLen))

	key := make([]byte, keyLen)
	c, err := NewAES(key)
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, bufLen)
	tweak := make([]byte, 16)
	binary.LittleEndian.PutUint64(tweak[0:8], 42)
	c.Encrypt(buf, buf, tweak)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Decrypt(buf, buf, tweak)
	}
	sink = buf
}

func BenchmarkXCTR2(b *testing.B) {
	bench := func(b *testing.B) {
		for _, keyLen := range benchKeySizes {
			for _, bufLen := range bufSizes {
				name := fmt.Sprintf("AES-%d/%d", keyLen*8, bufLen)
				b.Run(name, func(b *testing.B) {
					benchmarkXCTR2(b, keyLen, bufLen)
				})
			}
		}
	}
	runBench(b, bench)
}

func benchmarkXCTR2(b *testing.B, keyLen, bufLen int) {
	b.SetBytes(int64(bufLen))

	buf := make([]byte, bufLen)
	c, err := NewAES(make([]byte, keyLen))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.xctr(buf, buf, &c.s)
	}
	sink = buf
}
