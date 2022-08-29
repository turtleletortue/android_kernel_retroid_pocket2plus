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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>

#include "sprd_panel.h"
#include "sprd_dsi.h"
#include "sprd_dpu.h"
#include "sysfs_display.h"
#include "../dsi/sprd_dsi_api.h"

static uint8_t input_param[255];
static uint8_t input_len;
static uint8_t read_buf[64];
static uint8_t lp_cmd_en = true;

static ssize_t phy_freq_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	int ret;
	int freq;
	struct sprd_dsi *dsi = dev_get_drvdata(dev);

	ret = kstrtoint(buf, 10, &freq);
	if (ret) {
		pr_err("Invalid input freq\n");
		return -EINVAL;
	}

	if (freq == dsi->phy->ctx.freq) {
		pr_info("input freq is the same as old\n");
		return count;
	}

	pr_info("input freq is %d\n", freq);

	dsi->phy->ctx.freq = freq;
	dsi->ctx.byte_clk = freq / 8;

	return count;
}

static ssize_t phy_freq_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int ret;
	struct sprd_dsi *dsi = dev_get_drvdata(dev);

	ret = snprintf(buf, PAGE_SIZE, "%u Kbps\n", dsi->phy->ctx.freq);

	return ret;
}
static DEVICE_ATTR_RW(phy_freq);

static ssize_t byte_clk_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int ret;
	struct sprd_dsi *dsi = dev_get_drvdata(dev);

	ret = snprintf(buf, PAGE_SIZE, "%u KHz\n", dsi->ctx.byte_clk);

	return ret;
}
static DEVICE_ATTR_RO(byte_clk);

static ssize_t escape_clk_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	int ret;
	int esc_clk;
	struct sprd_dsi *dsi = dev_get_drvdata(dev);

	ret = kstrtoint(buf, 10, &esc_clk);
	if (ret) {
		pr_err("Invalid input clock value\n");
		return -EINVAL;
	}

	if (esc_clk == dsi->ctx.esc_clk) {
		pr_info("input clock is the same as old\n");
		return count;
	}

	pr_info("input clock value is %d\n", esc_clk);

	dsi->ctx.esc_clk = esc_clk;

	return count;
}

static ssize_t escape_clk_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int ret;
	struct sprd_dsi *dsi = dev_get_drvdata(dev);

	ret = snprintf(buf, PAGE_SIZE, "%u KHz\n", dsi->ctx.esc_clk);

	return ret;
}
static DEVICE_ATTR_RW(escape_clk);

/*
 * usage:
 *	(1) echo reg count > gen_read
 *	(2) cat gen_read
 *
 * example:
 *	(1) echo 0x0A 0x01 > gen_read
 *	(2) cat gen_read
 *
 *	return as follow:
 *	data[0] = 0x9c
 */
static ssize_t gen_read_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	int len;

	if (pm_runtime_suspended(dev->parent)) {
		pr_err("dsi is not initialized\n");
		return -ENXIO;
	}

	len = str_to_u8_array(buf, 16, input_param);
	if (len == 1)
		input_param[1] = 1;

	mipi_dsi_set_maximum_return_packet_size(dsi->slave, input_param[1]);
	mipi_dsi_generic_read(dsi->slave, &input_param[0], 1,
			read_buf, input_param[1]);

	return count;
}

static ssize_t gen_read_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	int i;
	int ret = 0;

	for (i = 0; i < input_param[1]; i++)
		ret += snprintf(buf + ret, PAGE_SIZE,
				"data[%d] = 0x%02x\n",
				i, read_buf[i]);

	return ret;
}
static DEVICE_ATTR_RW(gen_read);

/*
 * usage:
 *	echo reg param0 param1 param2 ... > gen_write
 *
 * example:
 *	echo 0x2B 0x10 0x1A 0x5C > gen_write
 *	echo 0x28 > gen_write
 *	echo 0x10 > gen_write
 */
static ssize_t gen_write_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	int i;

	if (pm_runtime_suspended(dev->parent)) {
		pr_err("dsi is not initialized\n");
		return -ENXIO;
	}

	input_len = str_to_u8_array(buf, 16, input_param);

	for (i = 0; i < input_len; i++)
		pr_info("param[%d] = 0x%x\n", i, input_param[i]);

	mipi_dsi_generic_write(dsi->slave, input_param, input_len);

	return count;
}

static ssize_t gen_write_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	int i;
	int ret = 0;

	for (i = 0; i < input_len; i++)
		ret += snprintf(buf + ret, PAGE_SIZE,
				"param[%d] = 0x%02x\n",
				i, input_param[i]);

	return ret;
}
static DEVICE_ATTR_RW(gen_write);

/*
 * usage:
 *	(1) echo reg count > dcs_read
 *	(2) cat dcs_read
 *
 * example:
 *	(1) echo 0x0A 0x01 > dcs_read
 *	(2) cat dcs_read
 *
 *	return as follow:
 *	data[0] = 0x9c
 */
static ssize_t dcs_read_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	int len;

	if (pm_runtime_suspended(dev->parent)) {
		pr_err("dsi is not initialized\n");
		return -ENXIO;
	}

	len = str_to_u8_array(buf, 16, input_param);
	if (len == 1)
		input_param[1] = 1;

	mipi_dsi_set_maximum_return_packet_size(dsi->slave, input_param[1]);
	mipi_dsi_dcs_read(dsi->slave, input_param[0],
			  read_buf, input_param[1]);

	return count;
}

static ssize_t dcs_read_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	int i;
	int ret = 0;

	for (i = 0; i < input_param[1]; i++)
		ret += snprintf(buf + ret, PAGE_SIZE,
				"data[%d] = 0x%02x\n",
				i, read_buf[i]);

	return ret;
}
static DEVICE_ATTR_RW(dcs_read);

/*
 * usage:
 *	echo reg param0 param1 param2 ... > dcs_write
 *
 * example:
 *	echo 0x2B 0x10 0x1A 0x5C > dcs_write
 *	echo 0x28 > dcs_write
 *	echo 0x10 > dcs_write
 */
static ssize_t dcs_write_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	int i;

	if (pm_runtime_suspended(dev->parent)) {
		pr_err("dsi is not initialized\n");
		return -ENXIO;
	}

	input_len = str_to_u8_array(buf, 16, input_param);

	for (i = 0; i < input_len; i++)
		pr_info("param[%d] = 0x%x\n", i, input_param[i]);

	mipi_dsi_dcs_write_buffer(dsi->slave, input_param, input_len);

	return count;
}

static ssize_t dcs_write_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	int i;
	int ret = 0;

	for (i = 0; i < input_len; i++)
		ret += snprintf(buf + ret, PAGE_SIZE,
				"param[%d] = 0x%02x\n",
				i, input_param[i]);

	return ret;
}
static DEVICE_ATTR_RW(dcs_write);

static ssize_t work_mode_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);

	if (pm_runtime_suspended(dev->parent)) {
		pr_err("dsi is not initialized\n");
		return -ENXIO;
	}

	if (!strncmp(buf, "video", strlen("video")))
		sprd_dsi_set_work_mode(dsi, DSI_MODE_VIDEO);
	else if (!strncmp(buf, "cmd", strlen("cmd")))
		sprd_dsi_set_work_mode(dsi, DSI_MODE_CMD);

	return count;
}

static ssize_t work_mode_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	int ret = 0;
	int mode;

	if (pm_runtime_suspended(dev->parent))
		return snprintf(buf, PAGE_SIZE, "dsi was closed\n");

	mode = sprd_dsi_get_work_mode(dsi);

	if (mode == DSI_MODE_CMD)
		ret = snprintf(buf, PAGE_SIZE, "cmd\n");
	else
		ret = snprintf(buf, PAGE_SIZE, "video\n");

	return ret;
}
static DEVICE_ATTR_RW(work_mode);

static ssize_t lp_cmd_en_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	uint8_t enable = 0;

	if (pm_runtime_suspended(dev->parent)) {
		pr_err("dsi is not initialized\n");
		return -ENXIO;
	}

	if (kstrtou8(buf, 10, &enable)) {
		pr_err("Invalid input\n");
		return -EINVAL;
	}

	lp_cmd_en = enable;
	sprd_dsi_lp_cmd_enable(dsi, enable);

	return count;
}

static ssize_t lp_cmd_en_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	int ret = 0;

	if (pm_runtime_suspended(dev->parent))
		return snprintf(buf, PAGE_SIZE, "dsi was closed\n");

	ret = snprintf(buf, PAGE_SIZE, "%d\n", lp_cmd_en);

	return ret;
}
static DEVICE_ATTR_RW(lp_cmd_en);

static ssize_t hs2lp_datalane_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	u32 val;

	if (kstrtouint(buf, 0, &val)) {
		pr_err("invalid input for hs2lp datalane\n");
		return -EINVAL;
	}

	dsi->ctx.data_hs2lp = val;

	return count;
}

static ssize_t hs2lp_datalane_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%u ns\n", dsi->ctx.data_hs2lp);
}
static DEVICE_ATTR_RW(hs2lp_datalane);

static ssize_t hs2lp_clklane_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	u32 val;

	if (kstrtouint(buf, 0, &val)) {
		pr_err("invalid input for hs2lp clklane\n");
		return -EINVAL;
	}

	dsi->ctx.clk_hs2lp = val;

	return count;
}

static ssize_t hs2lp_clklane_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%u ns\n", dsi->ctx.clk_hs2lp);
}
static DEVICE_ATTR_RW(hs2lp_clklane);

static ssize_t lp2hs_datalane_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	u32 val;

	if (kstrtouint(buf, 0, &val)) {
		pr_err("invalid input for lp2hs datalane\n");
		return -EINVAL;
	}

	dsi->ctx.data_lp2hs = val;

	return count;
}

static ssize_t lp2hs_datalane_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%u ns\n", dsi->ctx.data_lp2hs);
}
static DEVICE_ATTR_RW(lp2hs_datalane);

static ssize_t lp2hs_clklane_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	u32 val;

	if (kstrtouint(buf, 0, &val)) {
		pr_err("invalid input for lp2hs clklane\n");
		return -EINVAL;
	}

	dsi->ctx.clk_lp2hs = val;

	return count;
}

static ssize_t lp2hs_clklane_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%u ns\n", dsi->ctx.clk_lp2hs);
}
static DEVICE_ATTR_RW(lp2hs_clklane);

static ssize_t max_read_time_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	u32 val;

	if (kstrtouint(buf, 0, &val)) {
		pr_err("invalid input for max read time\n");
		return -EINVAL;
	}

	dsi->ctx.max_rd_time = val;

	return count;
}

static ssize_t max_read_time_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%u ns\n", dsi->ctx.max_rd_time);
}
static DEVICE_ATTR_RW(max_read_time);

static ssize_t int0_mask_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	struct sprd_dpu *dpu = crtc_to_dpu(dsi->encoder.crtc);
	u32 mask = 0xffffffff;

	if (kstrtou32(buf, 16, &mask)) {
		pr_err("Invalid input\n");
		return -EINVAL;
	}

	if (dsi->ctx.int0_mask != mask)
		dsi->ctx.int0_mask = mask;

	if (pm_runtime_suspended(dev->parent)) {
		pr_err("dsi was suspended\n");
		return -ENXIO;
	}

	sprd_dsi_int_mask(dsi, 0);
	sprd_dpu_stop(dpu);
	sprd_dsi_state_reset(dsi);
	sprd_dpu_run(dpu);

	return count;
}

static ssize_t int0_mask_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	int ret = 0;

	ret = snprintf(buf, PAGE_SIZE, "0x%08x\n", dsi->ctx.int0_mask);

	return ret;
}
static DEVICE_ATTR_RW(int0_mask);

static ssize_t int1_mask_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	struct sprd_dpu *dpu = crtc_to_dpu(dsi->encoder.crtc);
	u32 mask = 0xffffffff;

	if (kstrtou32(buf, 16, &mask)) {
		pr_err("Invalid input\n");
		return -EINVAL;
	}

	if (dsi->ctx.int1_mask != mask)
		dsi->ctx.int1_mask = mask;

	if (pm_runtime_suspended(dev->parent)) {
		pr_err("dsi was suspended\n");
		return -ENXIO;
	}

	sprd_dsi_int_mask(dsi, 1);
	sprd_dpu_stop(dpu);
	sprd_dsi_state_reset(dsi);
	sprd_dpu_run(dpu);

	return count;
}

static ssize_t int1_mask_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	int ret = 0;

	ret = snprintf(buf, PAGE_SIZE, "0x%08x\n", dsi->ctx.int1_mask);

	return ret;
}
static DEVICE_ATTR_RW(int1_mask);

static ssize_t state_reset_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct sprd_dsi *dsi = dev_get_drvdata(dev);
	struct sprd_dpu *dpu = crtc_to_dpu(dsi->encoder.crtc);

	if (pm_runtime_suspended(dev->parent)) {
		pr_err("dsi is not initialized\n");
		return -ENXIO;
	}

	sprd_dpu_stop(dpu);
	sprd_dsi_state_reset(dsi);
	sprd_dpu_run(dpu);

	return count;
}
static DEVICE_ATTR_WO(state_reset);

static ssize_t suspend_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	pm_runtime_put_sync(dev->parent);
	return count;
}
static DEVICE_ATTR_WO(suspend);

static ssize_t resume_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	pm_runtime_get_sync(dev->parent);
	return count;
}
static DEVICE_ATTR_WO(resume);

static struct attribute *dsi_attrs[] = {
	&dev_attr_phy_freq.attr,
	&dev_attr_byte_clk.attr,
	&dev_attr_escape_clk.attr,
	&dev_attr_gen_read.attr,
	&dev_attr_gen_write.attr,
	&dev_attr_dcs_read.attr,
	&dev_attr_dcs_write.attr,
	&dev_attr_work_mode.attr,
	&dev_attr_lp_cmd_en.attr,
	&dev_attr_hs2lp_datalane.attr,
	&dev_attr_hs2lp_clklane.attr,
	&dev_attr_lp2hs_datalane.attr,
	&dev_attr_lp2hs_clklane.attr,
	&dev_attr_max_read_time.attr,
	&dev_attr_int0_mask.attr,
	&dev_attr_int1_mask.attr,
	&dev_attr_state_reset.attr,
	&dev_attr_suspend.attr,
	&dev_attr_resume.attr,
	NULL,
};
ATTRIBUTE_GROUPS(dsi);

int sprd_dsi_sysfs_init(struct device *dev)
{
	int rc;

	rc = sysfs_create_groups(&dev->kobj, dsi_groups);
	if (rc)
		pr_err("create dsi attr node failed, rc=%d\n", rc);

	return rc;
}
EXPORT_SYMBOL(sprd_dsi_sysfs_init);

MODULE_AUTHOR("Leon He <leon.he@unisoc.com>");
MODULE_DESCRIPTION("Add dsi attribute nodes for userspace");
MODULE_LICENSE("GPL v2");
