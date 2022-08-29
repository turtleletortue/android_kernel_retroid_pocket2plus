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

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/mfd/syscon.h>
#include <linux/regmap.h>

#include "sprd_dpu.h"

static struct clk *clk_ap_ahb_disp_eb;

static struct dpu_clk_context {
	struct clk *clk_src_96m;
	struct clk *clk_src_128m;
	struct clk *clk_src_153m6;
	struct clk *clk_src_192m;
	struct clk *clk_src_256m;
	struct clk *clk_src_307m2;
	struct clk *clk_src_384m;
	struct clk *clk_dpu_core;
	struct clk *clk_dpu_dpi;
} dpu_clk_ctx;

static struct qos_thres {
	u8 awqos_thres;
	u8 arqos_thres;
} qos_cfg;

static const u32 dpu_core_clk[] = {
	153600000,
	192000000,
	256000000,
	307200000,
	384000000
};

static const u32 dpi_clk_src[] = {
	96000000,
	128000000,
	153600000
};

static struct dpu_glb_context {
	unsigned int enable_reg;
	unsigned int mask_bit;

	struct regmap *regmap;
} ctx_reset, ctx_qos;

static struct clk *val_to_clk(struct dpu_clk_context *ctx, u32 val)
{
	switch (val) {
	case 96000000:
		return ctx->clk_src_96m;
	case 128000000:
		return ctx->clk_src_128m;
	case 153600000:
		return ctx->clk_src_153m6;
	case 192000000:
		return ctx->clk_src_192m;
	case 256000000:
		return ctx->clk_src_256m;
	case 307200000:
		return ctx->clk_src_307m2;
	case 384000000:
		return ctx->clk_src_384m;
	default:
		pr_err("invalid clock value %u\n", val);
		return NULL;
	}
}

static int dpu_clk_parse_dt(struct dpu_context *ctx,
				struct device_node *np)
{
	struct dpu_clk_context *clk_ctx = &dpu_clk_ctx;

	clk_ctx->clk_src_96m =
		of_clk_get_by_name(np, "clk_src_96m");
	clk_ctx->clk_src_128m =
		of_clk_get_by_name(np, "clk_src_128m");
	clk_ctx->clk_src_153m6 =
		of_clk_get_by_name(np, "clk_src_153m6");
	clk_ctx->clk_src_192m =
		of_clk_get_by_name(np, "clk_src_192m");
	clk_ctx->clk_src_256m =
		of_clk_get_by_name(np, "clk_src_256m");
	clk_ctx->clk_src_307m2 =
		of_clk_get_by_name(np, "clk_src_307m2");
	clk_ctx->clk_src_384m =
		of_clk_get_by_name(np, "clk_src_384m");
	clk_ctx->clk_dpu_core =
		of_clk_get_by_name(np, "clk_dpu_core");
	clk_ctx->clk_dpu_dpi =
		of_clk_get_by_name(np, "clk_dpu_dpi");

	if (IS_ERR(clk_ctx->clk_src_96m)) {
		pr_warn("read clk_src_96m failed\n");
		clk_ctx->clk_src_96m = NULL;
	}

	if (IS_ERR(clk_ctx->clk_src_128m)) {
		pr_warn("read clk_src_128m failed\n");
		clk_ctx->clk_src_128m = NULL;
	}

	if (IS_ERR(clk_ctx->clk_src_153m6)) {
		pr_warn("read clk_src_153m6 failed\n");
		clk_ctx->clk_src_153m6 = NULL;
	}

	if (IS_ERR(clk_ctx->clk_src_192m)) {
		pr_warn("read clk_src_192m failed\n");
		clk_ctx->clk_src_192m = NULL;
	}

	if (IS_ERR(clk_ctx->clk_src_256m)) {
		pr_warn("read clk_src_256m failed\n");
		clk_ctx->clk_src_256m = NULL;
	}

	if (IS_ERR(clk_ctx->clk_src_307m2)) {
		pr_warn("read clk_src_307m2 failed\n");
		clk_ctx->clk_src_307m2 = NULL;
	}

	if (IS_ERR(clk_ctx->clk_src_384m)) {
		pr_warn("read clk_src_384m failed\n");
		clk_ctx->clk_src_384m = NULL;
	}

	if (IS_ERR(clk_ctx->clk_dpu_core)) {
		pr_warn("read clk_dpu_core failed\n");
		clk_ctx->clk_dpu_core = NULL;
	}

	if (IS_ERR(clk_ctx->clk_dpu_dpi)) {
		pr_warn("read clk_dpu_dpi failed\n");
		clk_ctx->clk_dpu_dpi = NULL;
	}

	return 0;
}

static u32 calc_dpu_core_clk(void)
{
	return dpu_core_clk[ARRAY_SIZE(dpu_core_clk) - 1];
}

static u32 calc_dpi_clk_src(u32 pclk)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dpi_clk_src); i++) {
		if ((dpi_clk_src[i] % pclk) == 0)
			return dpi_clk_src[i];
	}

	pr_err("calc DPI_CLK_SRC failed, use default\n");
	return 96000000;
}

static int dpu_clk_init(struct dpu_context *ctx)
{
	int ret;
	u32 dpu_core_val;
	u32 dpi_src_val;
	struct clk *clk_src;
	struct dpu_clk_context *clk_ctx = &dpu_clk_ctx;

	dpu_core_val = calc_dpu_core_clk();
	dpi_src_val = calc_dpi_clk_src(ctx->vm.pixelclock);

	pr_info("DPU_CORE_CLK = %u, DPI_CLK_SRC = %u\n",
		dpu_core_val, dpi_src_val);
	pr_info("dpi clock is %lu\n", ctx->vm.pixelclock);

	clk_src = val_to_clk(clk_ctx, dpu_core_val);
	ret = clk_set_parent(clk_ctx->clk_dpu_core, clk_src);
	if (ret)
		pr_warn("set dpu core clk source failed\n");

	clk_src = val_to_clk(clk_ctx, dpi_src_val);
	ret = clk_set_parent(clk_ctx->clk_dpu_dpi, clk_src);
	if (ret)
		pr_warn("set dpi clk source failed\n");

	ret = clk_set_rate(clk_ctx->clk_dpu_dpi, ctx->vm.pixelclock);
	if (ret)
		pr_err("dpu update dpi clk rate failed\n");

	return ret;
}

static int dpu_clk_enable(struct dpu_context *ctx)
{
	int ret;
	struct dpu_clk_context *clk_ctx = &dpu_clk_ctx;

	ret = clk_prepare_enable(clk_ctx->clk_dpu_core);
	if (ret) {
		pr_err("enable clk_dpu_core error\n");
		return ret;
	}

	ret = clk_prepare_enable(clk_ctx->clk_dpu_dpi);
	if (ret) {
		pr_err("enable clk_dpu_dpi error\n");
		clk_disable_unprepare(clk_ctx->clk_dpu_core);
		return ret;
	}

	return 0;
}

static int dpu_clk_disable(struct dpu_context *ctx)
{
	struct dpu_clk_context *clk_ctx = &dpu_clk_ctx;

	clk_disable_unprepare(clk_ctx->clk_dpu_dpi);
	clk_disable_unprepare(clk_ctx->clk_dpu_core);

	clk_set_parent(clk_ctx->clk_dpu_dpi, clk_ctx->clk_src_96m);
	clk_set_parent(clk_ctx->clk_dpu_core, clk_ctx->clk_src_153m6);

	return 0;
}

static int dpu_glb_parse_dt(struct dpu_context *ctx,
				struct device_node *np)
{
	unsigned int syscon_args[2];
	struct device_node *qos_np = NULL;
	int ret;

	ctx_reset.regmap = syscon_regmap_lookup_by_name(np, "reset");
	if (IS_ERR(ctx_reset.regmap)) {
		pr_warn("failed to map dpu glb reg: reset\n");
		return PTR_ERR(ctx_reset.regmap);
	}

	ret = syscon_get_args_by_name(np, "reset", 2, syscon_args);
	if (ret == 2) {
		ctx_reset.enable_reg = syscon_args[0];
		ctx_reset.mask_bit = syscon_args[1];
	} else {
		pr_warn("failed to parse dpu glb reg: reset\n");
	}

	clk_ap_ahb_disp_eb =
		of_clk_get_by_name(np, "clk_ap_ahb_disp_eb");
	if (IS_ERR(clk_ap_ahb_disp_eb)) {
		pr_warn("read clk_ap_ahb_disp_eb failed\n");
		clk_ap_ahb_disp_eb = NULL;
	}

	ctx_qos.regmap = syscon_regmap_lookup_by_name(np, "qos");
	if (IS_ERR(ctx_qos.regmap)) {
		pr_warn("failed to map dpu glb reg: qos\n");
		return PTR_ERR(ctx_qos.regmap);
	}

	ret = syscon_get_args_by_name(np, "qos", 2, syscon_args);
	if (ret == 2) {
		ctx_qos.enable_reg = syscon_args[0];
		ctx_qos.mask_bit = syscon_args[1];
	} else {
		pr_warn("failed to parse dpu glb reg: qos\n");
	}

	qos_np = of_parse_phandle(np, "sprd,qos", 0);
	if (!qos_np)
		pr_warn("can't find dpu qos cfg node\n");

	ret = of_property_read_u8(qos_np, "awqos-threshold",
					&qos_cfg.awqos_thres);
	if (ret)
		pr_warn("read awqos-threshold failed, use default\n");

	ret = of_property_read_u8(qos_np, "arqos-threshold",
					&qos_cfg.arqos_thres);
	if (ret)
		pr_warn("read arqos-threshold failed, use default\n");

	return 0;
}

static void dpu_glb_enable(struct dpu_context *ctx)
{
	int ret;

	ret = clk_prepare_enable(clk_ap_ahb_disp_eb);
	if (ret) {
		pr_err("enable clk_aon_apb_disp_eb failed!\n");
		return;
	}
}

static void dpu_glb_disable(struct dpu_context *ctx)
{
	clk_disable_unprepare(clk_ap_ahb_disp_eb);
}

static void dpu_reset(struct dpu_context *ctx)
{
	regmap_update_bits(ctx_reset.regmap,
		    ctx_reset.enable_reg,
		    ctx_reset.mask_bit,
		    ctx_reset.mask_bit);
	udelay(10);
	regmap_update_bits(ctx_reset.regmap,
		    ctx_reset.enable_reg,
		    ctx_reset.mask_bit,
		    (unsigned int)(~ctx_reset.mask_bit));
}

static void dpu_power_domain(struct dpu_context *ctx, int enable)
{
	if (enable)
		regmap_update_bits(ctx_qos.regmap,
			    ctx_qos.enable_reg,
			    ctx_qos.mask_bit,
			    qos_cfg.awqos_thres |
			    qos_cfg.arqos_thres << 4);
}

static struct dpu_clk_ops dpu_clk_ops = {
	.parse_dt = dpu_clk_parse_dt,
	.init = dpu_clk_init,
	.enable = dpu_clk_enable,
	.disable = dpu_clk_disable,
};

static struct dpu_glb_ops dpu_glb_ops = {
	.parse_dt = dpu_glb_parse_dt,
	.reset = dpu_reset,
	.enable = dpu_glb_enable,
	.disable = dpu_glb_disable,
	.power = dpu_power_domain,
};

static struct ops_entry clk_entry = {
	.ver = "sharkl5",
	.ops = &dpu_clk_ops,
};

static struct ops_entry glb_entry = {
	.ver = "sharkl5",
	.ops = &dpu_glb_ops,
};

static int __init dpu_glb_register(void)
{
	dpu_clk_ops_register(&clk_entry);
	dpu_glb_ops_register(&glb_entry);
	return 0;
}

subsys_initcall(dpu_glb_register);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("kevin.tang@unisoc.com");
MODULE_DESCRIPTION("sprd sharkl5 dpu global and clk regs config");
