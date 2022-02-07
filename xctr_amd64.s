// Code generated by command: go run asm.go -out out/xctr_amd64.s -stubs out/stub_amd64.go -pkg hctr2. DO NOT EDIT.

//go:build gc && !purego

#include "textflag.h"

// func xctrAsm(nr int, xk *uint32, out *byte, in *byte, nblocks int, iv *[16]byte)
// Requires: AES, SSE2
TEXT ·xctrAsm(SB), NOSPLIT, $0-48
	MOVQ nr+0(FP), AX
	MOVQ xk+8(FP), CX
	MOVQ out+16(FP), DX
	MOVQ in+24(FP), BX
	MOVQ nblocks+32(FP), SI
	MOVQ iv+40(FP), DI

	// Load every fourth round key starting with the initial
	// round key addition.
	// Initialize per-block constants.
	// Counter index.
	MOVQ $0x00000001, R8

	// Offset into dst, src.
	XORQ R9, R9

	// Nonce.
	MOVOU (DI), X0
	MOVQ  SI, R10
	ANDQ  $0x03, R10
	JZ    initWideLoop
	SHLQ  $0x04, R10

singleLoop:
	MOVQ R8, X1
	PXOR X0, X1
	XORQ DI, DI

	// Initial round key addition.
	MOVOU (CX)(DI*1), X2
	PXOR  X2, X1
	ADDQ  $0x00000010, DI

	// Choose between AES-128, AES-192, and AES-256.
	CMPQ AX, $0x0000000c
	JEQ  enc192x1
	JLT  enc128x1

	// Rounds 1 and 2.
	MOVOU  (CX)(DI*1), X2
	AESENC X2, X1
	MOVOU  16(CX)(DI*1), X2
	AESENC X2, X1
	ADDQ   $0x00000020, DI

	// Rounds 3 and 4.
enc192x1:
	MOVOU  (CX)(DI*1), X2
	AESENC X2, X1
	MOVOU  16(CX)(DI*1), X2
	AESENC X2, X1
	ADDQ   $0x00000020, DI

	// Rounds 5 through 14.
enc128x1:
	MOVOU      (CX)(DI*1), X2
	AESENC     X2, X1
	MOVOU      16(CX)(DI*1), X2
	AESENC     X2, X1
	MOVOU      32(CX)(DI*1), X2
	AESENC     X2, X1
	MOVOU      48(CX)(DI*1), X2
	AESENC     X2, X1
	MOVOU      64(CX)(DI*1), X2
	AESENC     X2, X1
	MOVOU      80(CX)(DI*1), X2
	AESENC     X2, X1
	MOVOU      96(CX)(DI*1), X2
	AESENC     X2, X1
	MOVOU      112(CX)(DI*1), X2
	AESENC     X2, X1
	MOVOU      128(CX)(DI*1), X2
	AESENC     X2, X1
	MOVOU      144(CX)(DI*1), X2
	AESENCLAST X2, X1
	MOVOU      (BX)(R9*1), X2
	PXOR       X2, X1
	MOVOU      X1, (DX)(R9*1)
	ADDQ       $0x10, R9
	ADDQ       $0x01, R8
	CMPQ       R10, R9
	JNE        singleLoop

initWideLoop:
	SHRQ $0x02, SI
	JZ   done
	SHLQ $0x06, SI
	ADDQ R9, SI

wideLoop:
	MOVQ R8, X1
	INCQ R8
	MOVQ R8, X2
	INCQ R8
	MOVQ R8, X3
	INCQ R8
	MOVQ R8, X4
	INCQ R8
	PXOR X0, X1
	PXOR X0, X2
	PXOR X0, X3
	PXOR X0, X4
	XORQ DI, DI

	// Initial round key addition.
	MOVOU (CX)(DI*1), X5
	PXOR  X5, X1
	PXOR  X5, X2
	PXOR  X5, X3
	PXOR  X5, X4
	ADDQ  $0x00000010, DI

	// Choose between AES-128, AES-192, and AES-256.
	CMPQ AX, $0x0000000c
	JEQ  enc192x4
	JLT  enc128x4

	// Rounds 1 and 2.
	MOVOU  (CX)(DI*1), X5
	AESENC X5, X1
	AESENC X5, X2
	AESENC X5, X3
	AESENC X5, X4
	MOVOU  16(CX)(DI*1), X5
	AESENC X5, X1
	AESENC X5, X2
	AESENC X5, X3
	AESENC X5, X4
	ADDQ   $0x00000020, DI

	// Rounds 3 and 4.
enc192x4:
	MOVOU  (CX)(DI*1), X5
	AESENC X5, X1
	AESENC X5, X2
	AESENC X5, X3
	AESENC X5, X4
	MOVOU  16(CX)(DI*1), X5
	AESENC X5, X1
	AESENC X5, X2
	AESENC X5, X3
	AESENC X5, X4
	ADDQ   $0x00000020, DI

	// Rounds 5 through 14.
enc128x4:
	MOVOU      (CX)(DI*1), X5
	AESENC     X5, X1
	AESENC     X5, X2
	AESENC     X5, X3
	AESENC     X5, X4
	MOVOU      16(CX)(DI*1), X5
	AESENC     X5, X1
	AESENC     X5, X2
	AESENC     X5, X3
	AESENC     X5, X4
	MOVOU      32(CX)(DI*1), X5
	AESENC     X5, X1
	AESENC     X5, X2
	AESENC     X5, X3
	AESENC     X5, X4
	MOVOU      48(CX)(DI*1), X5
	AESENC     X5, X1
	AESENC     X5, X2
	AESENC     X5, X3
	AESENC     X5, X4
	MOVOU      64(CX)(DI*1), X5
	AESENC     X5, X1
	AESENC     X5, X2
	AESENC     X5, X3
	AESENC     X5, X4
	MOVOU      80(CX)(DI*1), X5
	AESENC     X5, X1
	AESENC     X5, X2
	AESENC     X5, X3
	AESENC     X5, X4
	MOVOU      96(CX)(DI*1), X5
	AESENC     X5, X1
	AESENC     X5, X2
	AESENC     X5, X3
	AESENC     X5, X4
	MOVOU      112(CX)(DI*1), X5
	AESENC     X5, X1
	AESENC     X5, X2
	AESENC     X5, X3
	AESENC     X5, X4
	MOVOU      128(CX)(DI*1), X5
	AESENC     X5, X1
	AESENC     X5, X2
	AESENC     X5, X3
	AESENC     X5, X4
	MOVOU      144(CX)(DI*1), X5
	AESENCLAST X5, X1
	AESENCLAST X5, X2
	AESENCLAST X5, X3
	AESENCLAST X5, X4
	MOVOU      (BX)(R9*1), X5
	MOVOU      16(BX)(R9*1), X6
	MOVOU      32(BX)(R9*1), X7
	MOVOU      48(BX)(R9*1), X8
	PXOR       X5, X1
	PXOR       X6, X2
	PXOR       X7, X3
	PXOR       X8, X4
	MOVOU      X1, (DX)(R9*1)
	MOVOU      X2, 16(DX)(R9*1)
	MOVOU      X3, 32(DX)(R9*1)
	MOVOU      X4, 48(DX)(R9*1)
	ADDQ       $0x40, R9
	CMPQ       SI, R9
	JNE        wideLoop

done:
	RET