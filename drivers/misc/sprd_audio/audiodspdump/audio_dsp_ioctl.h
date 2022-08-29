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

#ifndef _AUDIO_DSP_IOCTL_H
#define _AUDIO_DSP_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define DSPLOG_CMD_MARGIC 'X'

#define DSPLOG_CMD_LOG_ENABLE		_IOW(DSPLOG_CMD_MARGIC, 0, int)
#define DSPLOG_CMD_LOG_PATH_SET		_IOW(DSPLOG_CMD_MARGIC, 1, int)
#define DSPLOG_CMD_LOG_PACKET_ENABLE	_IOW(DSPLOG_CMD_MARGIC, 2, int)
#define DSPLOG_CMD_PCM_PATH_SET		_IOW(DSPLOG_CMD_MARGIC, 3, int)
#define DSPLOG_CMD_PCM_ENABLE		_IOW(DSPLOG_CMD_MARGIC, 4, int)
#define DSPLOG_CMD_PCM_PACKET_ENABLE	_IOW(DSPLOG_CMD_MARGIC, 5, int)
#define DSPLOG_CMD_DSPASSERT		_IOW(DSPLOG_CMD_MARGIC, 6, int)
#define DSPLOG_CMD_DSPDUMP_ENABLE	_IOW(DSPLOG_CMD_MARGIC, 7, int)
#define DSPLOG_CMD_TIMEOUTDUMP_ENABLE	_IOW(DSPLOG_CMD_MARGIC, 8, int)


#endif
