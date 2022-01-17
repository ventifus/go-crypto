// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build arm64 && gc && !purego
// +build arm64,gc,!purego

#include "textflag.h"
#include "go_asm.h"

#ifdef GOOS_darwin

#define vxarq_u64_63_x2(v0, v1, v2, v3, t0, t1) \
	VXAR $63, v1.D2, v0.D2, v0.D2 \
	VXAR $63, v3.D2, v2.D2, v2.D2

#define vxarq_u64_32_x2(v0, v1, v2, v3) \
	VXAR $32, v1.D2, v0.D2, v0.D2 \
	VXAR $32, v3.D2, v2.D2, v2.D2

#define vxarq_u64_24_x2(v0, v1, v2, v3, t0, t1) \
	VXAR $24, v1.D2, v0.D2, v0.D2 \
	VXAR $24, v3.D2, v2.D2, v2.D2

#define vxarq_u64_16_x2(v0, v1, v2, v3, t0, t1) \
	VXAR $16, v1.D2, v0.D2, v0.D2 \
	VXAR $16, v3.D2, v2.D2, v2.D2

#else

#define vxarq_u64_63_x2(v0, v1, v2, v3, t0, t1) \
	VEOR  v2.B16, v3.B16, t1.B16 \
	VEOR  v0.B16, v1.B16, t0.B16 \
	VUSHR $63, t1.D2, v2.D2      \
	VUSHR $63, t0.D2, v0.D2      \
	VSLI  $1, t1.D2, v2.D2       \
	VSLI  $1, t0.D2, v0.D2

#define vxarq_u64_32_x2(v0, v1, v2, v3) \
	VEOR   v3.B16, v2.B16, v2.B16 \
	VEOR   v1.B16, v0.B16, v0.B16 \
	VREV64 v2.S4, v2.S4           \
	VREV64 v0.S4, v0.S4

#define vxarq_u64_24_x2(v0, v1, v2, v3, t0, t1) \
	VEOR v3.B16, v2.B16, v2.B16     \
	VEOR v1.B16, v0.B16, v0.B16     \
	VEXT $8, v2.B16, v2.B16, t1.B16 \
	VEXT $8, v0.B16, v0.B16, t0.B16 \
	VEXT $3, v2.B8, v2.B8, v2.B8    \
	VEXT $3, v0.B8, v0.B8, v0.B8    \
	VEXT $3, t1.B8, t1.B8, t1.B8    \
	VEXT $3, t0.B8, t0.B8, t0.B8    \
	VMOV t1.D[0], v2.D[1]           \
	VMOV t0.D[0], v0.D[1]

#define vxarq_u64_16_x2(v0, v1, v2, v3, t0, t1) \
	VEOR v3.B16, v2.B16, v2.B16     \
	VEOR v1.B16, v0.B16, v0.B16     \
	VEXT $8, v2.B16, v2.B16, t1.B16 \
	VEXT $8, v0.B16, v0.B16, t0.B16 \
	VEXT $2, v2.B8, v2.B8, v2.B8    \
	VEXT $2, v0.B8, v0.B8, v0.B8    \
	VEXT $2, t1.B8, t1.B8, t1.B8    \
	VEXT $2, t0.B8, t0.B8, t0.B8    \
	VMOV t1.D[0], v2.D[1]           \
	VMOV t0.D[0], v0.D[1]

#endif

#define HALF_ROUND(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, b0, b1, b2, b3, t0, t1) \
	VADD b0.D2, row1l.D2, row1l.D2                      \
	VADD b1.D2, row1h.D2, row1h.D2                      \
	VADD row2l.D2, row1l.D2, row1l.D2                   \
	VADD row2h.D2, row1h.D2, row1h.D2                   \
	vxarq_u64_32_x2(row4l, row1l, row4h, row1h)         \
	VADD row4l.D2, row3l.D2, row3l.D2                   \
	VADD row4h.D2, row3h.D2, row3h.D2                   \
	vxarq_u64_24_x2(row2l, row3l, row2h, row3h, t0, t1) \
	                                                    \
	VADD b2.D2, row1l.D2, row1l.D2                      \
	VADD b3.D2, row1h.D2, row1h.D2                      \
	VADD row2l.D2, row1l.D2, row1l.D2                   \
	VADD row2h.D2, row1h.D2, row1h.D2                   \
	vxarq_u64_16_x2(row4l, row1l, row4h, row1h, t0, t1) \
	VADD row4l.D2, row3l.D2, row3l.D2                   \
	VADD row4h.D2, row3h.D2, row3h.D2                   \
	vxarq_u64_63_x2(row2l, row3l, row2h, row3h, t0, t1) \

// t0 = row2l
// t1 = row4l
#define DIAGONALIZE(row2l, row4l, row2h, row4h, t0, t1) \
	VEXT $8, row2h.B16, row2l.B16, t0.B16    \
	VEXT $8, row4l.B16, row4h.B16, t1.B16    \
	VEXT $8, row2l.B16, row2h.B16, row2h.B16 \
	VEXT $8, row4h.B16, row4l.B16, row4h.B16

// t0 = row2l
// t1 = row4l
#define UNDIAGONALIZE(row2l, row4l, row2h, row4h, t0, t1) \
	VEXT $8, row2l.B16, row2h.B16, t0.B16    \
	VEXT $8, row4h.B16, row4l.B16, t1.B16    \
	VEXT $8, row2h.B16, row2l.B16, row2h.B16 \
	VEXT $8, row4l.B16, row4h.B16, row4h.B16

#define ROUND_1(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1) \
	VZIP1 m1.D2, m0.D2, b0.D2                                                                  \
	VZIP1 m3.D2, m2.D2, b1.D2                                                                  \
	VZIP2 m1.D2, m0.D2, b2.D2                                                                  \
	VZIP2 m3.D2, m2.D2, b3.D2                                                                  \
	HALF_ROUND(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, b0, b1, b2, b3, t0, t1) \
	DIAGONALIZE(row2l, row4l, row2h, row4h, t0, t1)                                            \
	VZIP1 m5.D2, m4.D2, b0.D2                                                                  \
	VZIP1 m7.D2, m6.D2, b1.D2                                                                  \
	VZIP2 m5.D2, m4.D2, b2.D2                                                                  \
	VZIP2 m7.D2, m6.D2, b3.D2                                                                  \
	HALF_ROUND(row1l, t0, row3h, t1, row1h, row2h, row3l, row4h, b0, b1, b2, b3, row2l, row4l) \
	UNDIAGONALIZE(t0, t1, row2h, row4h, row2l, row4l)

#define ROUND_2(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1) \
	VZIP1 m2.D2, m7.D2, b0.D2                                                                  \
	VZIP2 m6.D2, m4.D2, b1.D2                                                                  \
	VZIP1 m4.D2, m5.D2, b2.D2                                                                  \
	VEXT  $8, m3.B16, m7.B16, b3.B16                                                           \
	HALF_ROUND(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, b0, b1, b2, b3, t0, t1) \
	DIAGONALIZE(row2l, row4l, row2h, row4h, t0, t1)                                            \
	VEXT  $8, m0.B16, m0.B16, b0.B16                                                           \
	VZIP2 m2.D2, m5.D2, b1.D2                                                                  \
	VZIP1 m1.D2, m6.D2, b2.D2                                                                  \
	VZIP2 m1.D2, m3.D2, b3.D2                                                                  \
	HALF_ROUND(row1l, t0, row3h, t1, row1h, row2h, row3l, row4h, b0, b1, b2, b3, row2l, row4l) \
	UNDIAGONALIZE(t0, t1, row2h, row4h, row2l, row4l)

#define ROUND_3(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1) \
	VEXT  $8, m6.B16, m5.B16, b0.B16                                                           \
	VZIP2 m7.D2, m2.D2, b1.D2                                                                  \
	VZIP1 m0.D2, m4.D2, b2.D2                                                                  \
	VMOV  m1.D[0], b3.D[0]                                                                     \
	VMOV  m6.D[1], b3.D[1]                                                                     \
	HALF_ROUND(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, b0, b1, b2, b3, t0, t1) \
	DIAGONALIZE(row2l, row4l, row2h, row4h, t0, t1)                                            \
	VMOV  m5.D[0], b0.D[0]                                                                     \
	VMOV  m1.D[1], b0.D[1]                                                                     \
	VZIP2 m4.D2, m3.D2, b1.D2                                                                  \
	VZIP1 m3.D2, m7.D2, b2.D2                                                                  \
	VEXT  $8, m2.B16, m0.B16, b3.B16                                                           \
	HALF_ROUND(row1l, t0, row3h, t1, row1h, row2h, row3l, row4h, b0, b1, b2, b3, row2l, row4l) \
	UNDIAGONALIZE(t0, t1, row2h, row4h, row2l, row4l)

#define ROUND_4(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1) \
	VZIP2 m1.D2, m3.D2, b0.D2                                                                  \
	VZIP2 m5.D2, m6.D2, b1.D2                                                                  \
	VZIP2 m0.D2, m4.D2, b2.D2                                                                  \
	VZIP1 m7.D2, m6.D2, b3.D2                                                                  \
	HALF_ROUND(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, b0, b1, b2, b3, t0, t1) \
	DIAGONALIZE(row2l, row4l, row2h, row4h, t0, t1)                                            \
	VMOV  m1.D[0], b0.D[0]                                                                     \
	VMOV  m2.D[0], b1.D[0]                                                                     \
	VMOV  m2.D[1], b0.D[1]                                                                     \
	VMOV  m7.D[1], b1.D[1]                                                                     \
	VZIP1 m5.D2, m3.D2, b2.D2                                                                  \
	VZIP1 m4.D2, m0.D2, b3.D2                                                                  \
	HALF_ROUND(row1l, t0, row3h, t1, row1h, row2h, row3l, row4h, b0, b1, b2, b3, row2l, row4l) \
	UNDIAGONALIZE(t0, t1, row2h, row4h, row2l, row4l)

#define ROUND_5(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1) \
	VZIP2 m2.D2, m4.D2, b0.D2                                                                  \
	VZIP1 m5.D2, m1.D2, b1.D2                                                                  \
	VMOV  m0.D[0], b2.D[0]                                                                     \
	VMOV  m2.D[0], b3.D[0]                                                                     \
	VMOV  m3.D[1], b2.D[1]                                                                     \
	VMOV  m7.D[1], b3.D[1]                                                                     \
	HALF_ROUND(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, b0, b1, b2, b3, t0, t1) \
	DIAGONALIZE(row2l, row4l, row2h, row4h, t0, t1)                                            \
	VMOV  m7.D[0], b0.D[0]                                                                     \
	VMOV  m3.D[0], b1.D[0]                                                                     \
	VMOV  m5.D[1], b0.D[1]                                                                     \
	VMOV  m1.D[1], b1.D[1]                                                                     \
	VMOV  m4.D[0], b3.D[0]                                                                     \
	VEXT  $8, m6.B16, m0.B16, b2.B16                                                           \
	VMOV  m6.D[1], b3.D[1]                                                                     \
	HALF_ROUND(row1l, t0, row3h, t1, row1h, row2h, row3l, row4h, b0, b1, b2, b3, row2l, row4l) \
	UNDIAGONALIZE(t0, t1, row2h, row4h, row2l, row4l)

#define ROUND_6(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1) \
	VZIP1 m3.D2, m1.D2, b0.D2                                                                  \
	VZIP1 m4.D2, m0.D2, b1.D2                                                                  \
	VZIP1 m5.D2, m6.D2, b2.D2                                                                  \
	VZIP2 m1.D2, m5.D2, b3.D2                                                                  \
	HALF_ROUND(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, b0, b1, b2, b3, t0, t1) \
	DIAGONALIZE(row2l, row4l, row2h, row4h, t0, t1)                                            \
	VMOV  m2.D[0], b0.D[0]                                                                     \
	VZIP2 m0.D2, m7.D2, b1.D2                                                                  \
	VZIP2 m2.D2, m6.D2, b2.D2                                                                  \
	VMOV  m7.D[0], b3.D[0]                                                                     \
	VMOV  m3.D[1], b0.D[1]                                                                     \
	VMOV  m4.D[1], b3.D[1]                                                                     \
	HALF_ROUND(row1l, t0, row3h, t1, row1h, row2h, row3l, row4h, b0, b1, b2, b3, row2l, row4l) \
	UNDIAGONALIZE(t0, t1, row2h, row4h, row2l, row4l)

#define ROUND_7(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1) \
	VMOV  m6.D[0], b0.D[0]                                                                     \
	VZIP1 m2.D2, m7.D2, b1.D2                                                                  \
	VMOV  m0.D[1], b0.D[1]                                                                     \
	VZIP2 m7.D2, m2.D2, b2.D2                                                                  \
	VEXT  $8, m5.B16, m6.B16, b3.B16                                                           \
	HALF_ROUND(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, b0, b1, b2, b3, t0, t1) \
	DIAGONALIZE(row2l, row4l, row2h, row4h, t0, t1)                                            \
	VZIP1 m3.D2, m0.D2, b0.D2                                                                  \
	VEXT  $8, m4.B16, m4.B16, b1.B16                                                           \
	VMOV  m1.D[0], b3.D[0]                                                                     \
	VZIP2 m1.D2, m3.D2, b2.D2                                                                  \
	VMOV  m5.D[1], b3.D[1]                                                                     \
	HALF_ROUND(row1l, t0, row3h, t1, row1h, row2h, row3l, row4h, b0, b1, b2, b3, row2l, row4l) \
	UNDIAGONALIZE(t0, t1, row2h, row4h, row2l, row4l)

#define ROUND_8(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1) \
	VMOV  m6.D[0], b1.D[0]                                                                     \
	VZIP2 m3.D2, m6.D2, b0.D2                                                                  \
	VMOV  m1.D[1], b1.D[1]                                                                     \
	VEXT  $8, m7.B16, m5.B16, b2.B16                                                           \
	VZIP2 m4.D2, m0.D2, b3.D2                                                                  \
	HALF_ROUND(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, b0, b1, b2, b3, t0, t1) \
	DIAGONALIZE(row2l, row4l, row2h, row4h, t0, t1)                                            \
	VZIP2 m7.D2, m2.D2, b0.D2                                                                  \
	VZIP1 m1.D2, m4.D2, b1.D2                                                                  \
	VZIP1 m2.D2, m0.D2, b2.D2                                                                  \
	VZIP1 m5.D2, m3.D2, b3.D2                                                                  \
	HALF_ROUND(row1l, t0, row3h, t1, row1h, row2h, row3l, row4h, b0, b1, b2, b3, row2l, row4l) \
	UNDIAGONALIZE(t0, t1, row2h, row4h, row2l, row4l)

#define ROUND_9(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1) \
	VZIP1 m7.D2, m3.D2, b0.D2                                                                  \
	VEXT  $8, m0.B16, m5.B16, b1.B16                                                           \
	VZIP2 m4.D2, m7.D2, b2.D2                                                                  \
	VEXT  $8, m4.B16, m1.B16, b3.B16                                                           \
	HALF_ROUND(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, b0, b1, b2, b3, t0, t1) \
	DIAGONALIZE(row2l, row4l, row2h, row4h, t0, t1)                                            \
	VMOV  m6.B16, b0.B16                                                                       \
	VEXT  $8, m5.B16, m0.B16, b1.B16                                                           \
	VMOV  m1.D[0], b2.D[0]                                                                     \
	VMOV  m2.B16, b3.B16                                                                       \
	VMOV  m3.D[1], b2.D[1]                                                                     \
	HALF_ROUND(row1l, t0, row3h, t1, row1h, row2h, row3l, row4h, b0, b1, b2, b3, row2l, row4l) \
	UNDIAGONALIZE(t0, t1, row2h, row4h, row2l, row4l)

#define ROUND_10(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1) \
	VZIP1 m4.D2, m5.D2, b0.D2                                                                  \
	VZIP2 m0.D2, m3.D2, b1.D2                                                                  \
	VMOV  m3.D[0], b3.D[0]                                                                     \
	VZIP1 m2.D2, m1.D2, b2.D2                                                                  \
	VMOV  m2.D[1], b3.D[1]                                                                     \
	HALF_ROUND(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, b0, b1, b2, b3, t0, t1) \
	DIAGONALIZE(row2l, row4l, row2h, row4h, t0, t1)                                            \
	VZIP2 m4.D2, m7.D2, b0.D2                                                                  \
	VZIP2 m6.D2, m1.D2, b1.D2                                                                  \
	VEXT  $8, m7.B16, m5.B16, b2.B16                                                           \
	VZIP1 m0.D2, m6.D2, b3.D2                                                                  \
	HALF_ROUND(row1l, t0, row3h, t1, row1h, row2h, row3l, row4h, b0, b1, b2, b3, row2l, row4l) \
	UNDIAGONALIZE(t0, t1, row2h, row4h, row2l, row4l)

#define ROUND_11(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1) \
	VZIP1 m1.D2, m0.D2, b0.D2                                                                  \
	VZIP1 m3.D2, m2.D2, b1.D2                                                                  \
	VZIP2 m1.D2, m0.D2, b2.D2                                                                  \
	VZIP2 m3.D2, m2.D2, b3.D2                                                                  \
	HALF_ROUND(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, b0, b1, b2, b3, t0, t1) \
	DIAGONALIZE(row2l, row4l, row2h, row4h, t0, t1)                                            \
	VZIP1 m5.D2, m4.D2, b0.D2                                                                  \
	VZIP1 m7.D2, m6.D2, b1.D2                                                                  \
	VZIP2 m5.D2, m4.D2, b2.D2                                                                  \
	VZIP2 m7.D2, m6.D2, b3.D2                                                                  \
	HALF_ROUND(row1l, t0, row3h, t1, row1h, row2h, row3l, row4h, b0, b1, b2, b3, row2l, row4l) \
	UNDIAGONALIZE(t0, t1, row2h, row4h, row2l, row4l)

#define ROUND_12(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1) \
	VZIP1 m2.D2, m7.D2, b0.D2                                                                  \
	VZIP2 m6.D2, m4.D2, b1.D2                                                                  \
	VZIP1 m4.D2, m5.D2, b2.D2                                                                  \
	VEXT  $8, m3.B16, m7.B16, b3.B16                                                           \
	HALF_ROUND(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, b0, b1, b2, b3, t0, t1) \
	DIAGONALIZE(row2l, row4l, row2h, row4h, t0, t1)                                            \
	VEXT  $8, m0.B16, m0.B16, b0.B16                                                           \
	VZIP2 m2.D2, m5.D2, b1.D2                                                                  \
	VZIP1 m1.D2, m6.D2, b2.D2                                                                  \
	VZIP2 m1.D2, m3.D2, b3.D2                                                                  \
	HALF_ROUND(row1l, t0, row3h, t1, row1h, row2h, row3l, row4h, b0, b1, b2, b3, row2l, row4l) \
	UNDIAGONALIZE(t0, t1, row2h, row4h, row2l, row4l)

// func hashBlocksNEON(h *[8]uint64, c *[2]uint64, flag uint64, blocks []byte)
TEXT ·hashBlocksNEON(SB), NOSPLIT, $0-0
#define h_ptr R0
#define src_ptr R1
#define remain R2
#define c_ptr R3
#define c0 R4
#define c1 R5
#define f R6

#define row1l V1
#define row1h V2
#define row2l V3
#define row2h V4
#define row3l V5
#define row3h V6
#define row4l V7
#define row4h V8

#define b0 V9
#define b1 V10
#define b2 V11
#define b3 V12

#define m0 V13
#define m1 V14
#define m2 V15
#define m3 V16
#define m4 V17
#define m5 V18
#define m6 V19
#define m7 V20

#define h0 V21
#define h1 V22
#define h2 V23
#define h3 V24

#define t0 V25
#define t1 V26

#define iv0 V27
#define iv1 V28

	MOVD h+0(FP), h_ptr
	MOVD blocks_base+24(FP), src_ptr
	MOVD blocks_len+32(FP), remain
	MOVD c+8(FP), c_ptr
	MOVD flag+16(FP), f

	LDP (c_ptr), (c0, c1)

	VLD1.P 64(h_ptr), [h0.B16, h1.B16, h2.B16, h3.B16]

	VMOVQ $0x510e527fade682d1, $0x9b05688c2b3e6c1f, iv0
	VMOVQ $0x1f83d9abfb41bd6b, $0x5be0cd19137e2179, iv1

loop:
	ADDS $const_BlockSize, c0
	CINC HS, c1, c1

	// m[0..7] = block
	VLD1.P 64(src_ptr), [m0.B16, m1.B16, m2.B16, m3.B16]
	VLD1.P 64(src_ptr), [m4.B16, m5.B16, m6.B16, m7.B16]

	// row1l = h[0:2]
	// row2l = h[2:4]
	VMOV h0.B16, row1l.B16
	VMOV h1.B16, row1h.B16
	VMOV h2.B16, row2l.B16
	VMOV h3.B16, row2h.B16

	// row4l = (c0, c1) ^ (iv[4], iv[5])
	VMOV c0, row4l.D[0]
	VMOV c1, row4l.D[1]

	// row4h = (flag, 0) ^ (iv[6], iv[7])
	VEOR row4h.B16, row4h.B16, row4h.B16
	VMOV f, row4h.D[0]

	// row3l = iv[0:2]
	// row3h = iv[2:4]
	VMOVQ $0x6a09e667f3bcc908, $0xbb67ae8584caa73b, row3l
	VMOVQ $0x3c6ef372fe94f82b, $0xa54ff53a5f1d36f1, row3h

	VEOR iv0.B16, row4l.B16, row4l.B16
	VEOR iv1.B16, row4h.B16, row4h.B16

	ROUND_1(row1l,  row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1)
	ROUND_2(row1l,  row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1)
	ROUND_3(row1l,  row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1)
	ROUND_4(row1l,  row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1)
	ROUND_5(row1l,  row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1)
	ROUND_6(row1l,  row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1)
	ROUND_7(row1l,  row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1)
	ROUND_8(row1l,  row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1)
	ROUND_9(row1l,  row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1)
	ROUND_10(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1)
	ROUND_11(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1)
	ROUND_12(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h, m0, m1, m2, m3, m4, m5, m6, m7, b0, b1, b2, b3, t0, t1)

#ifdef GOOS_darwin
	VEOR3 row3l.B16, row1l.B16, h0.B16, h0.B16
	VEOR3 row3h.B16, row1h.B16, h1.B16, h1.B16
	VEOR3 row4l.B16, row2l.B16, h2.B16, h2.B16
	VEOR3 row4h.B16, row2h.B16, h3.B16, h3.B16

#else
	VEOR row1l.B16, h0.B16, h0.B16
	VEOR row3l.B16, h0.B16, h0.B16

	VEOR row1h.B16, h1.B16, h1.B16
	VEOR row3h.B16, h1.B16, h1.B16

	VEOR row2l.B16, h2.B16, h2.B16
	VEOR row4l.B16, h2.B16, h2.B16

	VEOR row2h.B16, h3.B16, h3.B16
	VEOR row4h.B16, h3.B16, h3.B16

#endif

	SUB $const_BlockSize, remain
	CMP $const_BlockSize, remain
	BGE loop

done:
	SUB    $64, h_ptr
	VST1.P [h0.B16, h1.B16, h2.B16, h3.B16], 64(h_ptr)
	STP    (c0, c1), (c_ptr)

	RET
