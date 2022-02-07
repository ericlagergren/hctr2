package main

import (
	"fmt"

	. "github.com/mmcloughlin/avo/build"
	// . "github.com/mmcloughlin/avo/gotypes"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

//go:generate go run asm.go -out ../hctr2_amd64.s -stubs ../stub_amd64.go -pkg hctr2

var mask Mem

func main() {
	Package("github.com/ericlagergren/hctr2")
	ConstraintExpr("gc,!purego")

	declareXctrAsm()

	Generate()
}

type state struct {
	nrounds Virtual
	xk      Mem
	idx     Virtual
	rkeys   [4]VecVirtual
}

func (s *state) init(nrounds Virtual, xk Mem) {
	s.nrounds = nrounds
	s.xk = xk
	s.idx = GP64()

	Comment(
		"Load every fourth round key starting with the initial",
		"round key addition.",
	)
	for i := range s.rkeys {
		// rk := XMM()
		// MOVOU(s.xk.Offset((i*4)*16), rk)
		// s.rkeys[i] = rk
		_ = i
	}
}

func (s *state) rk(i int) VecVirtual {
	switch i {
	case 0, 4, 8, 12:
		// return s.rkeys[i/4]
		fallthrough
	default:
		rk := XMM()
		MOVOU(s.xk.Idx(s.idx, 1).Offset(i*16), rk)
		return rk
	}
}

func (s *state) encrypt(v ...VecVirtual) {
	_ = v[0]

	suff := fmt.Sprintf("x%d", len(v))

	XORQ(s.idx, s.idx)

	Comment("Initial round key addition.")
	rk := s.rk(0)
	for i := range v {
		PXOR(rk, v[i])
	}
	ADDQ(U32(16), s.idx)

	Comment("Choose between AES-128, AES-192, and AES-256.")
	CMPQ(s.nrounds, U32(12))
	JEQ(LabelRef("enc192" + suff))
	JLT(LabelRef("enc128" + suff))

	Comment("Rounds 1 and 2.")
	Label("enc256" + suff)
	for r := 0; r < 2; r++ {
		rk := s.rk(r)
		for i := range v {
			AESENC(rk, v[i])
		}
	}
	ADDQ(U32(32), s.idx)

	Comment("Rounds 3 and 4.")
	Label("enc192" + suff)
	for r := 0; r < 2; r++ {
		rk := s.rk(r)
		for i := range v {
			AESENC(rk, v[i])
		}
	}
	ADDQ(U32(32), s.idx)

	Comment("Rounds 5 through 14.")
	Label("enc128" + suff)
	for r := 0; r < 9; r++ {
		rk := s.rk(r)
		for i := range v {
			AESENC(rk, v[i])
		}
	}
	rk = s.rk(9)
	for i := range v {
		AESENCLAST(rk, v[i])
	}
}

func declareXctrAsm() {
	TEXT("xctrAsm", NOSPLIT, "func(nr int, xk *uint32, out, in *byte, nblocks int, iv *[BlockSize]byte)")
	Pragma("noescape")

	nrounds := Load(Param("nr"), GP64()).(GPVirtual)
	xkPtr := Mem{Base: Load(Param("xk"), GP64())}
	dstPtr := Mem{Base: Load(Param("out"), GP64())}
	srcPtr := Mem{Base: Load(Param("in"), GP64())}
	nblocks := Load(Param("nblocks"), GP64())
	noncePtr := Mem{Base: Load(Param("iv"), GP64())}

	var s state
	s.init(nrounds, xkPtr)

	Comment("Initialize per-block constants.")
	Label("initLoops")

	Comment("Counter index.")
	idx := GP64()
	MOVQ(U32(1), idx)

	Comment("Offset into dst, src.")
	off := GP64()
	XORQ(off, off)

	const (
		// stride is the number of elements to process at a time.
		//
		// On my Apple M1, stride=4 and stride=8 exhibit the same
		// performance.
		stride = 4
	)

	// If stride > 4, nonce has to be reloaded each stride,
	// otherwise we run out of registers.
	var nonce VecVirtual
	loadNonce := func() VecVirtual {
		if nonce == nil {
			Comment("Nonce.")
			nonce = XMM()
			MOVOU(noncePtr, nonce)
		}
		return nonce
	}
	if stride > 4 {
		nonce = loadNonce()
	}

	Label("initSingleLoop")
	{
		nonce := loadNonce()

		nsingle := GP64()
		MOVQ(nblocks, nsingle)
		ANDQ(U8(stride-1), nsingle) // mod stride
		JZ(LabelRef("initWideLoop"))
		SHLQ(U8(4), nsingle) // multiply by 16

		Label("singleLoop")
		{
			ctr := XMM()
			MOVQ(idx, ctr)
			PXOR(nonce, ctr)

			s.encrypt(ctr)

			src := XMM()
			MOVOU(srcPtr.Idx(off, 1), src)
			PXOR(src, ctr)
			MOVOU(ctr, dstPtr.Idx(off, 1))

			ADDQ(U8(16), off)
			ADDQ(U8(1), idx)
			CMPQ(nsingle, off)
			JNE(LabelRef("singleLoop"))
		}
	}

	Label("initWideLoop")
	{
		nwide := GP64()
		MOVQ(nblocks, nwide)
		SHRQ(U8(2), nwide) // divide by stride
		JZ(LabelRef("done"))
		SHLQ(U8(6), nwide) // multiply by stride*16
		ADDQ(off, nwide)

		Label("wideLoop")
		{
			nonce := loadNonce()

			ctr := make([]VecVirtual, stride)
			for i := range ctr {
				ctr[i] = XMM()
				MOVQ(idx, ctr[i])
				INCQ(idx)
			}
			for i := range ctr {
				PXOR(nonce, ctr[i])
			}

			s.encrypt(ctr...)

			src := make([]VecVirtual, stride)
			for i := range src {
				src[i] = XMM()
				MOVOU(srcPtr.Idx(off, 1).Offset(i*16), src[i])
			}
			for i := range src {
				PXOR(src[i], ctr[i])
			}
			for i := range ctr {
				MOVOU(ctr[i], dstPtr.Idx(off, 1).Offset(i*16))
			}

			ADDQ(U8(stride*16), off)
			CMPQ(nwide, off)
			JNE(LabelRef("wideLoop"))
		}
	}

	Label("done")
	RET()
}
