/*
 * Copyright (C) 2019 UNISOC Communications Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _DPU_ENHANCE_PARAM_H
#define _DPU_ENHANCE_PARAM_H

u16 slp_lut[256] = {
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x1,
	0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
	0x1, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2,
	0x3, 0x3, 0x3, 0x3, 0x4, 0x4, 0x4, 0x4,
	0x5, 0x5, 0x5, 0x6, 0x6, 0x6, 0x7, 0x7,
	0x8, 0x8, 0x9, 0x9, 0xa, 0xa, 0xb, 0xc,
	0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x18, 0x19, 0x1b, 0x1c, 0x1e,
	0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2d, 0x2f,
	0x32, 0x35, 0x38, 0x3b, 0x3f, 0x42, 0x46, 0x4a,
	0x4e, 0x52, 0x57, 0x5c, 0x61, 0x66, 0x6b, 0x71,
	0x77, 0x7e, 0x84, 0x8b, 0x92, 0x9a, 0xa2, 0xaa,
	0xb2, 0xbb, 0xc4, 0xce, 0xd8, 0xe2, 0xec, 0xf7,
	0x102, 0x10e, 0x11a, 0x126, 0x132, 0x13f, 0x14c, 0x159,
	0x167, 0x175, 0x183, 0x191, 0x19f, 0x1ae, 0x1bc, 0x1cb,
	0x1da, 0x1e9, 0x1f8, 0x207, 0x216, 0x225, 0x234, 0x243,
	0x251, 0x260, 0x26e, 0x27c, 0x28a, 0x298, 0x2a6, 0x2b3,
	0x2c0, 0x2cd, 0x2d9, 0x2e5, 0x2f1, 0x2fd, 0x308, 0x313,
	0x31d, 0x327, 0x331, 0x33b, 0x344, 0x34d, 0x355, 0x35d,
	0x365, 0x36d, 0x374, 0x37b, 0x381, 0x388, 0x38e, 0x394,
	0x399, 0x39e, 0x3a3, 0x3a8, 0x3ad, 0x3b1, 0x3b5, 0x3b9,
	0x3bd, 0x3c0, 0x3c4, 0x3c7, 0x3ca, 0x3cd, 0x3d0, 0x3d2,
	0x3d5, 0x3d7, 0x3d9, 0x3db, 0x3dd, 0x3df, 0x3e1, 0x3e3,
	0x3e4, 0x3e6, 0x3e7, 0x3e9, 0x3ea, 0x3eb, 0x3ec, 0x3ed,
	0x3ee, 0x3ef, 0x3f0, 0x3f1, 0x3f2, 0x3f3, 0x3f3, 0x3f4
};

#endif /* _DPU_ENHANCE_PARAM_H */
