//go:build gc && !purego

#include "textflag.h"

#define ENCRYPT256x1(v0, rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14) \
	AESE  rk1.B16, v0.B16 \
	AESMC v0.B16, v0.B16  \
	AESE  rk2.B16, v0.B16 \
	AESMC v0.B16, v0.B16

#define ENCRYPT196x1(v0, rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14) \
	AESE  rk3.B16, v0.B16 \
	AESMC v0.B16, v0.B16  \
	AESE  rk4.B16, v0.B16 \
	AESMC v0.B16, v0.B16

#define ENCRYPT128x1(v0, rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14) \
	AESE  rk5.B16, v0.B16          \
	AESMC v0.B16, v0.B16           \
	AESE  rk6.B16, v0.B16          \
	AESMC v0.B16, v0.B16           \
	AESE  rk7.B16, v0.B16          \
	AESMC v0.B16, v0.B16           \
	AESE  rk8.B16, v0.B16          \
	AESMC v0.B16, v0.B16           \
	AESE  rk9.B16, v0.B16          \
	AESMC v0.B16, v0.B16           \
	AESE  rk10.B16, v0.B16         \
	AESMC v0.B16, v0.B16           \
	AESE  rk11.B16, v0.B16         \
	AESMC v0.B16, v0.B16           \
	AESE  rk12.B16, v0.B16         \
	AESMC v0.B16, v0.B16           \
	AESE  rk13.B16, v0.B16         \
	AESMC v0.B16, v0.B16           \
	AESE  rk14.B16, v0.B16         \
	VEOR  v0.B16, rk15.B16, v0.B16

#define ENCRYPT256x4(v0, v1, v2, v3, rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14) \
	AESE  rk1.B16, v0.B16 \
	AESE  rk1.B16, v1.B16 \
	AESE  rk1.B16, v2.B16 \
	AESE  rk1.B16, v3.B16 \
	                      \
	AESMC v0.B16, v0.B16  \
	AESMC v1.B16, v1.B16  \
	AESMC v2.B16, v2.B16  \
	AESMC v3.B16, v3.B16  \
	                      \
	AESE  rk2.B16, v0.B16 \
	AESE  rk2.B16, v1.B16 \
	AESE  rk2.B16, v2.B16 \
	AESE  rk2.B16, v3.B16 \
	                      \
	AESMC v0.B16, v0.B16  \
	AESMC v1.B16, v1.B16  \
	AESMC v2.B16, v2.B16  \
	AESMC v3.B16, v3.B16

#define ENCRYPT196x4(v0, v1, v2, v3, rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14) \
	AESE  rk3.B16, v0.B16 \
	AESE  rk3.B16, v1.B16 \
	AESE  rk3.B16, v2.B16 \
	AESE  rk3.B16, v3.B16 \
	                      \
	AESMC v0.B16, v0.B16  \
	AESMC v1.B16, v1.B16  \
	AESMC v2.B16, v2.B16  \
	AESMC v3.B16, v3.B16  \
	                      \
	AESE  rk4.B16, v0.B16 \
	AESE  rk4.B16, v1.B16 \
	AESE  rk4.B16, v2.B16 \
	AESE  rk4.B16, v3.B16 \
	                      \
	AESMC v0.B16, v0.B16  \
	AESMC v1.B16, v1.B16  \
	AESMC v2.B16, v2.B16  \
	AESMC v3.B16, v3.B16

#define ENCRYPT128x4(v0, v1, v2, v3, rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14) \
	AESE  rk5.B16, v0.B16          \
	AESE  rk5.B16, v1.B16          \
	AESE  rk5.B16, v2.B16          \
	AESE  rk5.B16, v3.B16          \
	                               \
	AESMC v0.B16, v0.B16           \
	AESMC v1.B16, v1.B16           \
	AESMC v2.B16, v2.B16           \
	AESMC v3.B16, v3.B16           \
	                               \
	AESE  rk6.B16, v0.B16          \
	AESE  rk6.B16, v1.B16          \
	AESE  rk6.B16, v2.B16          \
	AESE  rk6.B16, v3.B16          \
	                               \
	AESMC v0.B16, v0.B16           \
	AESMC v1.B16, v1.B16           \
	AESMC v2.B16, v2.B16           \
	AESMC v3.B16, v3.B16           \
	                               \
	AESE  rk7.B16, v0.B16          \
	AESE  rk7.B16, v1.B16          \
	AESE  rk7.B16, v2.B16          \
	AESE  rk7.B16, v3.B16          \
	                               \
	AESMC v0.B16, v0.B16           \
	AESMC v1.B16, v1.B16           \
	AESMC v2.B16, v2.B16           \
	AESMC v3.B16, v3.B16           \
	                               \
	AESE  rk8.B16, v0.B16          \
	AESE  rk8.B16, v1.B16          \
	AESE  rk8.B16, v2.B16          \
	AESE  rk8.B16, v3.B16          \
	                               \
	AESMC v0.B16, v0.B16           \
	AESMC v1.B16, v1.B16           \
	AESMC v2.B16, v2.B16           \
	AESMC v3.B16, v3.B16           \
	                               \
	AESE  rk9.B16, v0.B16          \
	AESE  rk9.B16, v1.B16          \
	AESE  rk9.B16, v2.B16          \
	AESE  rk9.B16, v3.B16          \
	                               \
	AESMC v0.B16, v0.B16           \
	AESMC v1.B16, v1.B16           \
	AESMC v2.B16, v2.B16           \
	AESMC v3.B16, v3.B16           \
	                               \
	AESE  rk10.B16, v0.B16         \
	AESE  rk10.B16, v1.B16         \
	AESE  rk10.B16, v2.B16         \
	AESE  rk10.B16, v3.B16         \
	                               \
	AESMC v0.B16, v0.B16           \
	AESMC v1.B16, v1.B16           \
	AESMC v2.B16, v2.B16           \
	AESMC v3.B16, v3.B16           \
	                               \
	AESE  rk11.B16, v0.B16         \
	AESE  rk11.B16, v1.B16         \
	AESE  rk11.B16, v2.B16         \
	AESE  rk11.B16, v3.B16         \
	                               \
	AESMC v0.B16, v0.B16           \
	AESMC v1.B16, v1.B16           \
	AESMC v2.B16, v2.B16           \
	AESMC v3.B16, v3.B16           \
	                               \
	AESE  rk12.B16, v0.B16         \
	AESE  rk12.B16, v1.B16         \
	AESE  rk12.B16, v2.B16         \
	AESE  rk12.B16, v3.B16         \
	                               \
	AESMC v0.B16, v0.B16           \
	AESMC v1.B16, v1.B16           \
	AESMC v2.B16, v2.B16           \
	AESMC v3.B16, v3.B16           \
	                               \
	AESE  rk13.B16, v0.B16         \
	AESE  rk13.B16, v1.B16         \
	AESE  rk13.B16, v2.B16         \
	AESE  rk13.B16, v3.B16         \
	                               \
	AESMC v0.B16, v0.B16           \
	AESMC v1.B16, v1.B16           \
	AESMC v2.B16, v2.B16           \
	AESMC v3.B16, v3.B16           \
	                               \
	AESE  rk14.B16, v0.B16         \
	AESE  rk14.B16, v1.B16         \
	AESE  rk14.B16, v2.B16         \
	AESE  rk14.B16, v3.B16         \
	                               \
	VEOR  v0.B16, rk15.B16, v0.B16 \
	VEOR  v1.B16, rk15.B16, v1.B16 \
	VEOR  v2.B16, rk15.B16, v2.B16 \
	VEOR  v3.B16, rk15.B16, v3.B16

// func xctrAsm(nr int, xk *uint32, out, in *byte, nblocks int, iv *[BlockSize]byte)
TEXT ·xctrAsm(SB), NOSPLIT, $0-48
#define nrounds R0
#define xk_ptr R1
#define dst_ptr R2
#define src_ptr R3
#define remain R4
#define nonce_ptr R5
#define nwide R6
#define nsingle R7

#define idx R8
#define idx0 R9
#define idx1 R10
#define idx2 R11
#define idx3 R12

#define n0 R13
#define n1 R14

#define nonce V0

#define rk1 V1
#define rk2 V2
#define rk3 V3
#define rk4 V4
#define rk5 V5
#define rk6 V6
#define rk7 V7
#define rk8 V8
#define rk9 V9
#define rk10 V10
#define rk11 V11
#define rk12 V12
#define rk13 V13
#define rk14 V14
#define rk15 V15
#define rk16 V16

#define dst0 V17
#define dst1 V18
#define dst2 V19
#define dst3 V20

#define src0 V21
#define src1 V22
#define src2 V23
#define src3 V24

#define ctr0 V25
#define ctr1 V26
#define ctr2 V27
#define ctr3 V28

#define ctr V29

	MOVD nr+0(FP), nrounds
	MOVD xk+8(FP), xk_ptr
	MOVD out+16(FP), dst_ptr
	MOVD in+24(FP), src_ptr
	MOVD nblocks+32(FP), remain
	MOVD iv+40(FP), nonce_ptr

	VLD1 (nonce_ptr), [nonce.B16]

loadKeys:
	CMP $12, nrounds
	BLT load128
	BEQ load196

load256:
	VLD1.P 32(xk_ptr), [rk1.B16, rk2.B16]

load196:
	VLD1.P 32(xk_ptr), [rk3.B16, rk4.B16]

load128:
	VLD1.P 64(xk_ptr), [rk5.B16, rk6.B16, rk7.B16, rk8.B16]
	VLD1.P 64(xk_ptr), [rk9.B16, rk10.B16, rk11.B16, rk12.B16]
	VLD1.P 48(xk_ptr), [rk13.B16, rk14.B16, rk15.B16]

initLoops:
	MOVD ZR, idx

	// The top half of the nonce is always XORed against zero, so
	// cache it. That just leaves the bottom half, which we can
	// use non-NEON instructions for.
	VEOR ctr.B16, ctr.B16, ctr.B16
	VEOR nonce.B16, ctr.B16, ctr.B16
	VMOV nonce.D[0], n0
	VMOV ctr.D[1], n1

initSingleLoop:
	ANDS $3, remain, nsingle
	BEQ  initWideLoop

	// Handle any blocks in excess of the stride.
singleLoop:
	VLD1.P 16(src_ptr), [src0.B16]

	VMOV n1, ctr.D[1]
	VMOV ctr.B16, ctr0.B16
	ADD  $1, idx, idx0
	EOR  n0, idx0, idx0
	VMOV idx0, ctr0.D[0]

	CMP $12, nrounds
	BLT enc128x1
	BEQ enc196x1

enc256x1:
	ENCRYPT256x1(ctr0, rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14)

enc196x1:
	ENCRYPT196x1(ctr0, rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14)

enc128x1:
	ENCRYPT128x1(ctr0, rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14)

	VEOR   src0.B16, ctr0.B16, dst0.B16
	VST1.P [dst0.B16], 16(dst_ptr)

	ADD  $1, idx
	SUBS $1, nsingle
	BNE  singleLoop

initWideLoop:
	ASR $2, remain, nwide
	CBZ nwide, done

	// Now handle the full stride.
wideLoop:
	VLD1.P 64(src_ptr), [src0.B16, src1.B16, src2.B16, src3.B16]

	VMOV n1, ctr.D[1]
	VMOV ctr.B16, ctr0.B16
	VMOV ctr.B16, ctr1.B16
	VMOV ctr.B16, ctr2.B16
	VMOV ctr.B16, ctr3.B16

	ADD $1, idx, idx0
	ADD $2, idx, idx1
	ADD $3, idx, idx2
	ADD $4, idx, idx3

	EOR n0, idx0, idx0
	EOR n0, idx1, idx1
	EOR n0, idx2, idx2
	EOR n0, idx3, idx3

	VMOV idx0, ctr0.D[0]
	VMOV idx1, ctr1.D[0]
	VMOV idx2, ctr2.D[0]
	VMOV idx3, ctr3.D[0]

	CMP $12, nrounds
	BLT enc128x4
	BEQ enc196x4

enc256x4:
	ENCRYPT256x4(ctr0, ctr1, ctr2, ctr3, rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14)

enc196x4:
	ENCRYPT196x4(ctr0, ctr1, ctr2, ctr3, rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14)

enc128x4:
	ENCRYPT128x4(ctr0, ctr1, ctr2, ctr3, rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14)

	VEOR   src0.B16, ctr0.B16, dst0.B16
	VEOR   src1.B16, ctr1.B16, dst1.B16
	VEOR   src2.B16, ctr2.B16, dst2.B16
	VEOR   src3.B16, ctr3.B16, dst3.B16
	VST1.P [dst0.B16, dst1.B16, dst2.B16, dst3.B16], 64(dst_ptr)

	ADD  $4, idx
	SUBS $1, nwide
	BNE  wideLoop

done:
	RET
