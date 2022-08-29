/*
 * Copyright (C) 2015 Spreadtrum Communications Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _GSP_R6P0_COEF_GENERATE_H_
#define _GSP_R6P0_COEF_GENERATE_H_

#include "gsp_r6p0_core.h"
#include "../gsp_debug.h"

#define LIST_SET_ENTRY_KEY(pEntry, i_w, i_h, o_w, o_h, h_t, v_t)\
{\
	pEntry->in_w = i_w;\
	pEntry->in_h = i_h;\
	pEntry->out_w = o_w;\
	pEntry->out_h = o_h;\
	pEntry->hor_tap = h_t;\
	pEntry->ver_tap = v_t;\
}

enum scale_kernel_type {
	GSP_SCL_TYPE_SINC = 0x00,
	GSP_SCL_TYPE_BI_CUBIC = 0x01,
	GSP_SCL_TYPE_MAX,
};

enum scale_win_type {
	GSP_SCL_WIN_RECT = 0x00,
	GSP_SCL_WIN_SINC = 0x01,
	GSP_SCL_WIN_MAX,
};

#define INTERPOLATION_STEP 128

/* log2(MAX_PHASE) */
#define FIX_POINT		4
#define MAX_PHASE		16
#define MAX_TAP			8
#define MAX_COEF_LEN	(MAX_PHASE * MAX_TAP + 1)

struct GSC_MEM_POOL {
	ulong begin_addr;
	ulong total_size;
	ulong used_size;
};

uint32_t *gsp_r6p0_gen_block_scaler_coef(struct gsp_r6p0_core *core,
						 uint32_t i_w,
						 uint32_t i_h,
						 uint32_t o_w,
						 uint32_t o_h,
						 uint32_t hor_tap,
						 uint32_t ver_tap);

#endif
