/*
 * Copyright (C) 2017-2018 Spreadtrum Communications Inc.
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

#include <linux/delay.h>
#include <video/sprd_mm.h>

#include "dcam_drv.h"

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "dcam_bin: %d %d %s : "\
	fmt, current->pid, __LINE__, __func__

int sprd_dcam_bin_path_init(enum dcam_id idx)
{
	enum dcam_drv_rtn rtn = DCAM_RTN_SUCCESS;
	struct dcam_path_desc *bin_path = sprd_dcam_drv_bin_path_get(idx);

	memset((void *)bin_path, 0x00, sizeof(*bin_path));
	bin_path->id = CAMERA_BIN_PATH;
	sprd_cam_queue_buf_init(&bin_path->buf_queue,
		sizeof(struct camera_frame),
		DCAM_BUF_QUEUE_LENGTH, "bin path buf_queue");
	sprd_cam_queue_frm_init(&bin_path->frame_queue,
		sizeof(struct camera_frame),
		DCAM_FRM_QUEUE_LENGTH + 1, "bin path frm_queue");

	bin_path->private_data = vzalloc(RDS_COEFF_SIZE);
	if (unlikely(!bin_path->private_data)) {
		pr_err("fail to alloc coeff table\n");
		return -ENOMEM;
	}
	rtn = sprd_cam_queue_buf_init(
		&bin_path->coeff_queue,
		sizeof(struct dcam_zoom_param),
		DCAM_SC_COEFF_BUF_COUNT,
		"dcam bin path coeff queue");
	if (rtn) {
		pr_err("fail to init coeff queue.\n");
		return rtn;
	}
	return rtn;
}

int sprd_dcam_bin_path_deinit(enum dcam_id idx)
{
	enum dcam_drv_rtn rtn = DCAM_RTN_SUCCESS;
	struct dcam_path_desc *bin_path = sprd_dcam_drv_bin_path_get(idx);

	if (DCAM_ADDR_INVALID(bin_path)) {
		pr_err("fail to get valid input ptr\n");
		return -EFAULT;
	}

	sprd_cam_queue_frm_deinit(&bin_path->frame_queue);
	sprd_cam_queue_buf_deinit(&bin_path->buf_queue);
	sprd_cam_queue_buf_deinit(&bin_path->coeff_queue);
	vfree(bin_path->private_data);
	memset(bin_path, 0x00, sizeof(*bin_path));

	return rtn;
}

int sprd_dcam_bin_path_map(struct cam_buf_info *buf_info)
{
	int ret = 0;

	if (!buf_info) {
		pr_err("fail to get valid input ptr\n");
		return -EINVAL;
	}

	ret = sprd_cam_buf_sg_table_get(buf_info);
	if (ret) {
		pr_err("fail to get buf sg table\n");
		return ret;
	}
	ret = sprd_cam_buf_addr_map(buf_info);
	if (ret) {
		pr_err("fail to map buf addr\n");
		return ret;
	}

	return ret;
}

int sprd_dcam_bin_path_unmap(enum dcam_id idx)
{
	enum dcam_drv_rtn rtn = DCAM_RTN_SUCCESS;
	struct dcam_path_desc *bin_path = sprd_dcam_drv_bin_path_get(idx);
	struct camera_frame *frame = NULL;
	struct camera_frame *res_frame = NULL;
	uint32_t i = 0;

	if (DCAM_ADDR_INVALID(bin_path)) {
		pr_err("fail to get valid input ptr\n");
		return -EFAULT;
	}

	if (bin_path->valid) {
		for (i = 0; i < bin_path->ion_buf_cnt; i++) {
			frame = &bin_path->ion_buffer[i];
			sprd_cam_buf_addr_unmap(&frame->buf_info);
		}

		bin_path->ion_buf_cnt = 0;
		res_frame = &bin_path->reserved_frame;
		if (sprd_cam_buf_is_valid(&res_frame->buf_info))
			sprd_cam_buf_addr_unmap(&res_frame->buf_info);
		memset((void *)res_frame, 0x00, sizeof(*res_frame));
	}

	return rtn;
}

void sprd_dcam_bin_path_clear(enum dcam_id idx)
{
	struct dcam_path_desc *bin_path = sprd_dcam_drv_bin_path_get(idx);

	sprd_cam_queue_buf_clear(&bin_path->buf_queue);
	sprd_cam_queue_frm_clear(&bin_path->frame_queue);
	sprd_cam_queue_buf_clear(&bin_path->coeff_queue);
	bin_path->valid = 0;
	bin_path->status = DCAM_ST_STOP;
	bin_path->output_frame_count = 0;
	bin_path->ion_buf_cnt = 0;
}

int sprd_dcam_bin_path_cfg_set(enum dcam_id idx,
	enum dcam_cfg_id id, void *param)
{
	enum dcam_drv_rtn rtn = DCAM_RTN_SUCCESS;
	struct dcam_path_desc *bin_path = sprd_dcam_drv_bin_path_get(idx);
	struct camera_addr *p_addr;

	if (DCAM_ADDR_INVALID(bin_path)) {
		pr_err("fail to get valid input ptr\n");
		return -EFAULT;
	}

	if ((unsigned long)(param) == 0) {
		pr_err("fail to get valid input ptr\n");
		return -DCAM_RTN_PARA_ERR;
	}

	switch (id) {
	case DCAM_PATH_BUF_NUM:
	{
		uint32_t *src = (uint32_t *)param;

		bin_path->buf_num = *src;
		break;
	}
	case DCAM_PATH_SRC_SEL:
	{
		uint32_t *src = (uint32_t *)param;

		bin_path->src_sel = *src;
		bin_path->valid_param.src_sel = 1;
		break;
	}
	case DCAM_PATH_INPUT_SIZE:
	{
		struct camera_size *size = (struct camera_size *)param;

		memcpy((void *)&bin_path->input_size, (void *)size,
			sizeof(struct camera_size));
		break;
	}
	case DCAM_PATH_INPUT_RECT:
	{
		struct camera_rect *rect = (struct camera_rect *)param;

		memcpy((void *)&bin_path->input_rect, (void *)rect,
			sizeof(struct camera_rect));
		break;
	}
	case DCAM_PATH_OUTPUT_FORMAT:
	{
		uint32_t *fmt = (uint32_t *)param;

		bin_path->output_format = *fmt;
		bin_path->valid_param.output_format = 1;
		break;
	}
	case DCAM_PATH_OUTPUT_LOOSE:
	{
		uint32_t *fmt = (uint32_t *)param;

		bin_path->is_loose = *fmt;
		break;
	}
	case DCAM_PATH_OUTPUT_ADDR:
		p_addr = (struct camera_addr *)param;

		if (p_addr->buf_info.type == CAM_BUF_USER_TYPE
			&& DCAM_YUV_ADDR_INVALID(p_addr->yaddr,
					p_addr->uaddr,
					p_addr->vaddr) &&
					p_addr->mfd_y == 0) {
			pr_err("fail to get valid addr!\n");
			rtn = DCAM_RTN_PATH_ADDR_ERR;
		} else if (p_addr->buf_info.type != CAM_BUF_USER_TYPE
			&& (p_addr->buf_info.client[0] == NULL
			|| p_addr->buf_info.handle[0] == NULL)) {
			pr_err("fail to get valid addr!\n");
			rtn = DCAM_RTN_PATH_ADDR_ERR;
		} else {
			struct camera_frame frame;

			memset((void *)&frame, 0x00, sizeof(frame));
			frame.yaddr = p_addr->yaddr;
			frame.uaddr = p_addr->uaddr;
			frame.vaddr = p_addr->vaddr;
			frame.yaddr_vir = p_addr->yaddr_vir;
			frame.uaddr_vir = p_addr->uaddr_vir;
			frame.vaddr_vir = p_addr->vaddr_vir;

			frame.type = CAMERA_BIN_PATH;
			frame.fid = bin_path->frame_base_id;

			frame.buf_info = p_addr->buf_info;
			frame.buf_info.idx = idx;
			frame.buf_info.dev = &s_dcam_pdev->dev;
			frame.buf_info.mfd[0] = p_addr->mfd_y;
			frame.buf_info.mfd[1] = p_addr->mfd_u;
			frame.buf_info.mfd[2] = p_addr->mfd_v;

			if (!(p_addr->buf_info.state
				&CAM_BUF_STATE_MAPPING_DCAM)) {
				rtn = sprd_dcam_bin_path_map(&frame.buf_info);
				if (rtn) {
					pr_err("fail to map dcam bin path!\n");
					rtn = DCAM_RTN_PATH_ADDR_ERR;
					break;
				}
			}

			if (!sprd_cam_queue_buf_write(&bin_path->buf_queue,
						&frame))
				bin_path->output_frame_count++;
			if (bin_path->ion_buf_cnt < bin_path->buf_num) {
				memcpy(&bin_path->ion_buffer
					[bin_path->ion_buf_cnt], &frame,
					sizeof(struct camera_frame));
				bin_path->ion_buf_cnt++;
			}

			DCAM_TRACE("y=0x%x u=0x%x v=0x%x mfd=0x%x 0x%x\n",
				p_addr->yaddr, p_addr->uaddr,
				p_addr->vaddr, frame.buf_info.mfd[0],
				frame.buf_info.mfd[1]);
		}
		break;
	case DCAM_PATH_OUTPUT_RESERVED_ADDR:
		p_addr = (struct camera_addr *)param;

		if (p_addr->buf_info.type == CAM_BUF_USER_TYPE
			&& DCAM_YUV_ADDR_INVALID(p_addr->yaddr,
					p_addr->uaddr,
					p_addr->vaddr) &&
					p_addr->mfd_y == 0) {
			pr_err("fail to get valid addr!\n");
			rtn = DCAM_RTN_PATH_ADDR_ERR;
		} else if (p_addr->buf_info.type != CAM_BUF_USER_TYPE
			&& (p_addr->buf_info.client[0] == NULL
			|| p_addr->buf_info.handle[0] == NULL)) {
			pr_err("fail to get valid addr!\n");
			rtn = DCAM_RTN_PATH_ADDR_ERR;
		} else {
			struct camera_frame *frame = NULL;

			frame = &bin_path->reserved_frame;

			memset((void *)frame, 0x00, sizeof(*frame));
			frame->yaddr = p_addr->yaddr;
			frame->uaddr = p_addr->uaddr;
			frame->vaddr = p_addr->vaddr;
			frame->yaddr_vir = p_addr->yaddr_vir;
			frame->uaddr_vir = p_addr->uaddr_vir;
			frame->vaddr_vir = p_addr->vaddr_vir;

			frame->buf_info = p_addr->buf_info;
			frame->buf_info.idx = idx;
			frame->buf_info.dev = &s_dcam_pdev->dev;
			frame->buf_info.mfd[0] = p_addr->mfd_y;
			frame->buf_info.mfd[1] = p_addr->mfd_u;
			frame->buf_info.mfd[2] = p_addr->mfd_v;

			/*may need update iommu here*/
			rtn = sprd_cam_buf_sg_table_get(&frame->buf_info);
			if (rtn) {
				pr_err("fail to cfg reserved output addr!\n");
				rtn = DCAM_RTN_PATH_ADDR_ERR;
				break;
			}
			rtn = sprd_cam_buf_addr_map(&frame->buf_info);

			DCAM_TRACE("y=0x%x u=0x%x v=0x%x mfd=0x%x 0x%x\n",
				p_addr->yaddr, p_addr->uaddr,
				p_addr->vaddr, p_addr->mfd_y,
				p_addr->mfd_u);
		}
		break;
	case DCAM_PATH_DATA_ENDIAN:
	{
		struct camera_endian_sel *endian
			= (struct camera_endian_sel *)param;

		if (endian->y_endian >= DCAM_ENDIAN_MAX) {
			rtn = DCAM_RTN_PATH_ENDIAN_ERR;
		} else {
			bin_path->data_endian.y_endian = endian->y_endian;
			bin_path->valid_param.data_endian = 1;
		}
		break;
	}
	case DCAM_PATH_OUTPUT_SIZE:
	{
		struct camera_size  *out_size
			= (struct camera_size  *)param;
		if (out_size->w > DCAM_BIN_WIDTH_MAX
			|| out_size->h > DCAM_BIN_HEIGHT_MAX) {
			rtn = DCAM_RTN_PATH_OUT_SIZE_ERR;
		} else {
			bin_path->output_size = *out_size;
		}
		break;
	}
	case DCAM_PATH_ENABLE:
		bin_path->valid = *(uint32_t *)param;
		break;
	case DCAM_PATH_ASSOC:
		bin_path->assoc_idx = *(uint32_t *)param;
		break;
	case DCAM_PATH_NEED_DOWNSIZER:
		bin_path->need_downsizer = *(uint32_t *)param;
		break;
	case DCAM_PATH_ZOOM_INFO:
		bin_path->zoom_info = *(struct zoom_info_t *)param;
		break;
	default:
		pr_err("fail to cfg dcam bin_path\n");
		break;
	}

	return -rtn;
}

int sprd_dcam_bin_path_next_frm_set(enum dcam_id idx)
{
	int use_reserve_frame = 0;
	uint32_t addr = 0;
	enum dcam_drv_rtn rtn = DCAM_RTN_SUCCESS;
	struct camera_frame frame;
	struct camera_frame *reserved_frame = NULL;
	struct dcam_path_desc *bin_path = sprd_dcam_drv_bin_path_get(idx);
	struct dcam_module *module = sprd_dcam_drv_module_get(idx);
	struct cam_frm_queue *p_heap = NULL;

	if (DCAM_ADDR_INVALID(bin_path) || DCAM_ADDR_INVALID(module)) {
		pr_err("fail to get valid input ptr\n");
		return -EFAULT;
	}

	memset((void *)&frame, 0x00, sizeof(frame));
	reserved_frame = &bin_path->reserved_frame;
	p_heap = &bin_path->frame_queue;

	if (sprd_cam_queue_buf_read(&bin_path->buf_queue, &frame) == 0 &&
		sprd_cam_buf_is_valid(&frame.buf_info)) {
		bin_path->output_frame_count--;
	} else {
		pr_info("DCAM%d: No free frame id %d\n",
			idx, module->frame_id);
		if (!sprd_cam_buf_is_valid(&reserved_frame->buf_info)) {
			pr_info("DCAM%d: No need to cfg frame buffer\n", idx);
			return -1;
		}
		memcpy(&frame, reserved_frame, sizeof(struct camera_frame));
		use_reserve_frame = 1;
	}

	if (frame.buf_info.dev == NULL)
		pr_info("DCAM%d next dev NULL %p\n", idx, frame.buf_info.dev);
	if (rtn) {
		pr_err("fail to get path addr\n");
		return rtn;
	}
	addr = frame.buf_info.iova[0] + frame.yaddr;

	DCAM_TRACE("DCAM%d: reserved %d iova[0]=0x%x mfd=0x%x 0x%x %p %p\n",
		idx, use_reserve_frame, (int)addr,
		frame.buf_info.mfd[0], frame.yaddr,
		frame.buf_info.client[0], frame.buf_info.handle[0]);

	DCAM_REG_WR(idx, DCAM_BIN_BASE_WADDR0, addr);

	frame.frame_id = module->frame_id;
	if (bin_path->need_downsizer) {
		frame.width = bin_path->out_size_latest.w;
		frame.height = bin_path->out_size_latest.h;
		frame.zoom_info = bin_path->zoom_info;
	}

	if (sprd_cam_queue_frm_enqueue(p_heap, &frame) == 0)
		DCAM_TRACE("success to enq frame buf\n");
	else
		rtn = DCAM_RTN_PATH_FRAME_LOCKED;

	return -rtn;
}

int sprd_dcam_bin_path_scaler_cfg(enum dcam_id idx)
{
	int i = 0;
	uint32_t reg_val = 0;
	unsigned long addr = 0;
	enum dcam_drv_rtn rtn = DCAM_RTN_SUCCESS;
	struct dcam_path_desc *bin_path = sprd_dcam_drv_bin_path_get(idx);
	struct camera_rect *rect = NULL;
	struct dcam_zoom_param zoom_param;
	uint32_t *coeff_ptr = NULL;

	bin_path->zoom_info.zoom_work = 1;
	rtn = sprd_cam_queue_buf_read(&bin_path->coeff_queue, &zoom_param);
	if (rtn) {
		bin_path->zoom_info.zoom_work = 0;
		pr_debug("no need to update bin path scaler param\n");
		return DCAM_RTN_SUCCESS;
	}
	pr_debug("crop_en %d,in_size %d %d in_rect %d %d %d %d out_size %d %d\n",
		zoom_param.bin_crop_bypass,
		zoom_param.in_size.w,
		zoom_param.in_size.h,
		zoom_param.in_rect.x,
		zoom_param.in_rect.y,
		zoom_param.in_rect.w,
		zoom_param.in_rect.h,
		zoom_param.out_size.w,
		zoom_param.out_size.h);
	bin_path->out_size_latest = zoom_param.out_size;
	bin_path->input_rect = zoom_param.in_rect;
	bin_path->output_size = zoom_param.out_size;
	bin_path->input_size = zoom_param.in_size;
	DCAM_REG_MWR(idx, DCAM_CAM_BIN_CFG, BIT_1, zoom_param.bin_crop_bypass);

	if (!zoom_param.bin_crop_bypass) {
		pr_debug("set crop_eb\n");
		DCAM_REG_MWR(idx, DCAM_CAM_BIN_CFG, BIT_1, BIT_1);

		addr = DCAM_BIN_CROP_START;
		rect = &zoom_param.in_rect;
		reg_val = (rect->x & 0xFFFF) |
			((rect->y & 0xFFFF) << 16);
		DCAM_REG_WR(idx, addr, reg_val);

		addr = DCAM_BIN_CROP_SIZE;
		reg_val = (rect->w & 0xFFFF) |
			((rect->h & 0xFFFF) << 16);
		DCAM_REG_WR(idx, addr, reg_val);
		DCAM_TRACE("bin path crop: %d %d %d %d\n",
			rect->x, rect->y, rect->w, rect->h);
	}
	if (zoom_param.in_rect.w == zoom_param.out_size.w
		&& zoom_param.in_rect.h == zoom_param.out_size.h) {
		DCAM_REG_MWR(idx, DCAM_CAM_BIN_CFG, 0x20, 0x20);
		pr_debug("raw scale and bin bypass\n");
	} else if (bin_path->need_downsizer == 0
		&& zoom_param.in_rect.w
				== 2 * zoom_param.out_size.w
		&& zoom_param.in_rect.h
				== 2 * zoom_param.out_size.h) {
		DCAM_REG_MWR(idx, DCAM_CAM_BIN_CFG, 0x2c, 0x00);
		pr_debug("bin 1/2\n");
	} else {
		pr_debug("rds\n");
		DCAM_REG_MWR(idx,
			DCAM_RDS_DES_SIZE, 0x7ff << 16 | 0xfff,
			zoom_param.out_size.h << 16 |
			zoom_param.out_size.w);
		coeff_ptr = zoom_param.coeff_ptr;
		for (i = 0; i < RDS_COEFF_SIZE; i += 4) {
			pr_debug("*coeff_ptr = 0x%x\n", *coeff_ptr);
			DCAM_REG_WR(idx,
				RDS_COEFF_START + i,
					*coeff_ptr++);
			}
		DCAM_REG_MWR(idx, DCAM_CAM_BIN_CFG, 0x28, 0x08);
	}
	sprd_dcam_drv_glb_reg_owr(idx, DCAM_CFG, BIT_2, DCAM_CFG_REG);

	return rtn;
}

int sprd_dcam_bin_path_start(enum dcam_id idx)
{
	int i = 0;
	uint32_t reg_val = 0;
	unsigned long addr = 0;
	enum dcam_drv_rtn rtn = DCAM_RTN_SUCCESS;
	struct dcam_path_desc *bin_path = sprd_dcam_drv_bin_path_get(idx);
	struct camera_rect *rect = NULL;
	uint32_t *coeff_ptr = (uint32_t *)bin_path->private_data;

	if (DCAM_ADDR_INVALID(bin_path)) {
		pr_err("fail to get valid input ptr\n");
		return -EFAULT;
	}

	if (bin_path->valid) {
		if (bin_path->valid_param.data_endian) {
			sprd_dcam_drv_glb_reg_mwr(idx, DCAM_PATH_ENDIAN,
				BIT_3 | BIT_2,
				bin_path->data_endian.y_endian << 2,
				DCAM_ENDIAN_REG);
			DCAM_TRACE("bin path: data_endian y=0x%x\n",
				bin_path->data_endian.y_endian);
		}

		if (bin_path->input_size.w != bin_path->input_rect.w
			|| bin_path->input_size.h != bin_path->input_rect.h) {
			pr_info("set crop_eb\n");

			DCAM_REG_MWR(idx, DCAM_CAM_BIN_CFG, BIT_1, BIT_1);

			addr = DCAM_BIN_CROP_START;
			rect = &bin_path->input_rect;
			reg_val = (rect->x & 0xFFFF) |
				((rect->y & 0xFFFF) << 16);
			DCAM_REG_WR(idx, addr, reg_val);

			addr = DCAM_BIN_CROP_SIZE;
			reg_val = (rect->w & 0xFFFF) |
				((rect->h & 0xFFFF) << 16);
			DCAM_REG_WR(idx, addr, reg_val);
			DCAM_TRACE("bin path crop: %d %d %d %d\n",
				rect->x, rect->y, rect->w, rect->h);
		}

		if (bin_path->valid_param.output_format) {
			DCAM_REG_MWR(idx, DCAM_CAM_BIN_CFG,
				BIT_0, bin_path->is_loose);
		}
		if (bin_path->need_downsizer)
			bin_path->out_size_latest =
				bin_path->output_size;

		rtn = sprd_dcam_bin_path_next_frm_set(idx);
		if (rtn) {
			pr_err("fail to set bin_path next frame\n");
			return -(rtn);
		}

		if (bin_path->input_rect.w == bin_path->output_size.w
			&& bin_path->input_rect.h == bin_path->output_size.h) {
			DCAM_REG_MWR(idx, DCAM_CAM_BIN_CFG, 0x20, 0x20);
			DCAM_TRACE("raw scale and bin bypass\n");
		} else if (bin_path->need_downsizer == 0
			&& bin_path->input_rect.w
					== 2 * bin_path->output_size.w
			&& bin_path->input_rect.h
					== 2 * bin_path->output_size.h) {
			DCAM_REG_MWR(idx, DCAM_CAM_BIN_CFG, 0x2c, 0x00);
			DCAM_TRACE("bin 1/2\n");
		} else {
			sprd_dcam_raw_sizer_coeff_gen(
				bin_path->input_rect.w,
				bin_path->input_rect.h,
				bin_path->output_size.w,
				bin_path->output_size.h,
				coeff_ptr, 0);

			DCAM_REG_MWR(idx,
				DCAM_RDS_DES_SIZE, 0x7ff << 16 | 0xfff,
				bin_path->output_size.h << 16 |
				bin_path->output_size.w);

			for (i = 0; i < RDS_COEFF_SIZE; i += 4)
				DCAM_REG_WR(idx,
					RDS_COEFF_START + i,
					*coeff_ptr++);

			DCAM_REG_MWR(idx, DCAM_CAM_BIN_CFG, 0x28, 0x08);
			DCAM_TRACE("raw scale\n");
		}
		sprd_dcam_drv_force_copy(idx, RDS_COPY);

		sprd_dcam_drv_glb_reg_owr(idx, DCAM_CFG, BIT_2, DCAM_CFG_REG);
		sprd_dcam_drv_force_copy(idx, BIN_COPY);
		bin_path->need_wait = 0;
		bin_path->status = DCAM_ST_START;
	}
	return rtn;
}
