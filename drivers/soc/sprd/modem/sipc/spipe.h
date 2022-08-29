/*
 * Copyright (C) 2018 Spreadtrum Communications Inc.
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

#ifndef __SPIPE_H
#define __SPIPE_H

struct spipe_init_data {
	char			*name;
	char			*sipc_name;
	u8			dst;
	u8			channel;
	u32		ringnr;
	u32		txbuf_size;
	u32		rxbuf_size;
};

#endif
