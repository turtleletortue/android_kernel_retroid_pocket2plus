// SPDX-License-Identifier: GPL-2.0
//
// Spreatrum SC9832e clock driver
//
// Copyright (C) 2018 Spreadtrum, Inc.
// Author: Chunyan Zhang <chunyan.zhang@spreadtrum.com>

#include <linux/clk-provider.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include <dt-bindings/clock/sprd,sc9832e-clk.h>

#include "common.h"
#include "composite.h"
#include "div.h"
#include "gate.h"
#include "mux.h"
#include "pll.h"

static SPRD_PLL_SC_GATE_CLK(isppll_gate, "isppll-gate", "ext-26m", 0x88,
				0x1000, BIT(0), CLK_IGNORE_UNUSED, 0, 240);
static SPRD_PLL_SC_GATE_CLK(mpll_gate, "mpll-gate", "ext-26m", 0x94,
				0x1000, BIT(0), CLK_IGNORE_UNUSED, 0, 240);
static SPRD_PLL_SC_GATE_CLK(dpll_gate, "dpll-gate", "ext-26m", 0x98,
				0x1000, BIT(0), CLK_IGNORE_UNUSED, 0, 240);
static SPRD_PLL_SC_GATE_CLK(lpll_gate, "lpll-gate", "ext-26m", 0x9c,
				0x1000, BIT(0), CLK_IGNORE_UNUSED, 0, 240);
static SPRD_PLL_SC_GATE_CLK(gpll_gate, "gpll-gate", "ext-26m", 0xa8,
				0x1000, BIT(0), CLK_IGNORE_UNUSED, 0, 240);

static struct sprd_clk_common *sc9832e_pmu_gate_clks[] = {
	/* address base is 0x402b0000 */
	&isppll_gate.common,
	&mpll_gate.common,
	&dpll_gate.common,
	&lpll_gate.common,
	&gpll_gate.common,
};

static struct clk_hw_onecell_data sc9832e_pmu_gate_hws = {
	.hws	= {
		[CLK_ISPPLL_GATE]	= &isppll_gate.common.hw,
		[CLK_MPLL_GATE]		= &mpll_gate.common.hw,
		[CLK_DPLL_GATE]		= &dpll_gate.common.hw,
		[CLK_LPLL_GATE]		= &lpll_gate.common.hw,
		[CLK_GPLL_GATE]		= &gpll_gate.common.hw,
	},
	.num	= CLK_PMU_GATE_NUM,
};

static const struct sprd_clk_desc sc9832e_pmu_gate_desc = {
	.clk_clks	= sc9832e_pmu_gate_clks,
	.num_clk_clks	= ARRAY_SIZE(sc9832e_pmu_gate_clks),
	.hw_clks        = &sc9832e_pmu_gate_hws,
};

static const struct freq_table ftable[4] = {
	{ .ibias = 0, .max_freq = 936000000ULL },
	{ .ibias = 1, .max_freq = 1248000000ULL },
	{ .ibias = 2, .max_freq = 1600000000ULL },
	{ .ibias = INVALID_MAX_IBIAS, .max_freq = INVALID_MAX_FREQ },
};

static const struct clk_bit_field f_twpll[PLL_FACT_MAX] = {
	{ .shift = 0,	.width = 0 },	/* lock_done	*/
	{ .shift = 0,	.width = 1 },	/* div_s	*/
	{ .shift = 1,	.width = 1 },	/* mod_en	*/
	{ .shift = 2,	.width = 1 },	/* sdm_en	*/
	{ .shift = 0,	.width = 0 },	/* refin	*/
	{ .shift = 6,	.width = 2 },	/* ibias	*/
	{ .shift = 8,	.width = 11 },	/* n		*/
	{ .shift = 55,	.width = 6 },	/* nint		*/
	{ .shift = 32,	.width = 23},	/* kint		*/
	{ .shift = 0,	.width = 0 },	/* prediv	*/
	{ .shift = 0,	.width = 0 },	/* postdiv	*/
};
static SPRD_PLL_WITH_ITABLE_1K(twpll_clk, "twpll", "ext-26m", 0xc,
				   2, ftable, f_twpll, 240);
static CLK_FIXED_FACTOR(twpll_768m, "twpll-768m", "twpll", 2, 1, 0);
static CLK_FIXED_FACTOR(twpll_384m, "twpll-384m", "twpll", 4, 1, 0);
static CLK_FIXED_FACTOR(twpll_192m, "twpll-192m", "twpll", 8, 1, 0);
static CLK_FIXED_FACTOR(twpll_96m, "twpll-96m", "twpll", 16, 1, 0);
static CLK_FIXED_FACTOR(twpll_48m, "twpll-48m", "twpll", 32, 1, 0);
static CLK_FIXED_FACTOR(twpll_24m, "twpll-24m", "twpll", 64, 1, 0);
static CLK_FIXED_FACTOR(twpll_12m, "twpll-12m", "twpll", 128, 1, 0);
static CLK_FIXED_FACTOR(twpll_512m, "twpll-512m", "twpll", 3, 1, 0);
static CLK_FIXED_FACTOR(twpll_256m, "twpll-256m", "twpll", 6, 1, 0);
static CLK_FIXED_FACTOR(twpll_128m, "twpll-128m", "twpll", 12, 1, 0);
static CLK_FIXED_FACTOR(twpll_64m, "twpll-64m", "twpll", 24, 1, 0);
static CLK_FIXED_FACTOR(twpll_307m2, "twpll-307m2", "twpll", 5, 1, 0);
static CLK_FIXED_FACTOR(twpll_219m4, "twpll-219m4", "twpll", 7, 1, 0);
static CLK_FIXED_FACTOR(twpll_170m6, "twpll-170m6", "twpll", 9, 1, 0);
static CLK_FIXED_FACTOR(twpll_153m6, "twpll-153m6", "twpll", 10, 1, 0);
static CLK_FIXED_FACTOR(twpll_76m8, "twpll-76m8", "twpll", 20, 1, 0);
static CLK_FIXED_FACTOR(twpll_51m2, "twpll-51m2", "twpll", 30, 1, 0);
static CLK_FIXED_FACTOR(twpll_38m4, "twpll-38m4", "twpll", 40, 1, 0);
static CLK_FIXED_FACTOR(twpll_19m2, "twpll-19m2", "twpll", 80, 1, 0);

#define f_lpll f_twpll
static SPRD_PLL_WITH_ITABLE_1K(lpll_clk, "lpll", "lpll-gate", 0x1c,
				   2, ftable, f_lpll, 240);
static CLK_FIXED_FACTOR(lpll_409m6, "lpll-409m6", "lpll", 3, 1, 0);
static CLK_FIXED_FACTOR(lpll_245m76, "lpll-245m76", "lpll", 5, 1, 0);

static const struct clk_bit_field f_gpll[PLL_FACT_MAX] = {
	{ .shift = 0,	.width = 0 },	/* lock_done	*/
	{ .shift = 1,	.width = 1 },	/* div_s	*/
	{ .shift = 2,	.width = 1 },	/* mod_en	*/
	{ .shift = 3,	.width = 1 },	/* sdm_en	*/
	{ .shift = 0,	.width = 0 },	/* refin	*/
	{ .shift = 7,	.width = 2 },	/* ibias	*/
	{ .shift = 9,	.width = 11 },	/* n		*/
	{ .shift = 55,	.width = 6 },	/* nint		*/
	{ .shift = 32,	.width = 23},	/* kint		*/
	{ .shift = 0,	.width = 0 },	/* prediv	*/
	{ .shift = 64,	.width = 1 },	/* postdiv	*/
};
static SPRD_PLL_WITH_ITABLE_K_FVCO(gpll_clk, "gpll", "gpll-gate", 0x2c,
				   3, ftable, f_gpll, 240,
				   1000, 1000, 1, 400000000);

static const struct clk_bit_field f_isppll[PLL_FACT_MAX] = {
	{ .shift = 0,	.width = 0 },	/* lock_done	*/
	{ .shift = 1,	.width = 1 },	/* div_s	*/
	{ .shift = 2,	.width = 1 },	/* mod_en	*/
	{ .shift = 3,	.width = 1 },	/* sdm_en	*/
	{ .shift = 0,	.width = 0 },	/* refin	*/
	{ .shift = 7,	.width = 2 },	/* ibias	*/
	{ .shift = 9,	.width = 11 },	/* n		*/
	{ .shift = 55,	.width = 6 },	/* nint		*/
	{ .shift = 32,	.width = 23},	/* kint		*/
	{ .shift = 0,	.width = 0 },	/* prediv	*/
	{ .shift = 0,	.width = 0 },	/* postdiv	*/
};
static SPRD_PLL_WITH_ITABLE_1K(isppll_clk, "isppll", "isppll-gate", 0x3c,
				   2, ftable, f_isppll, 240);
static CLK_FIXED_FACTOR(isppll_468m, "isppll-468m", "isppll", 2, 1, 0);

static struct sprd_clk_common *sc9832e_pll_clks[] = {
	/* address base is 0x403c0000 */
	&twpll_clk.common,
	&lpll_clk.common,
	&gpll_clk.common,
	&isppll_clk.common,
};

static struct clk_hw_onecell_data sc9832e_pll_hws = {
	.hws	= {
		[CLK_TWPLL]		= &twpll_clk.common.hw,
		[CLK_TWPLL_768M]	= &twpll_768m.hw,
		[CLK_TWPLL_384M]	= &twpll_384m.hw,
		[CLK_TWPLL_192M]	= &twpll_192m.hw,
		[CLK_TWPLL_96M]		= &twpll_96m.hw,
		[CLK_TWPLL_48M]		= &twpll_48m.hw,
		[CLK_TWPLL_24M]		= &twpll_24m.hw,
		[CLK_TWPLL_12M]		= &twpll_12m.hw,
		[CLK_TWPLL_512M]	= &twpll_512m.hw,
		[CLK_TWPLL_256M]	= &twpll_256m.hw,
		[CLK_TWPLL_128M]	= &twpll_128m.hw,
		[CLK_TWPLL_64M]		= &twpll_64m.hw,
		[CLK_TWPLL_307M2]	= &twpll_307m2.hw,
		[CLK_TWPLL_219M4]	= &twpll_219m4.hw,
		[CLK_TWPLL_170M6]	= &twpll_170m6.hw,
		[CLK_TWPLL_153M6]	= &twpll_153m6.hw,
		[CLK_TWPLL_76M8]	= &twpll_76m8.hw,
		[CLK_TWPLL_51M2]	= &twpll_51m2.hw,
		[CLK_TWPLL_38M4]	= &twpll_38m4.hw,
		[CLK_TWPLL_19M2]	= &twpll_19m2.hw,
		[CLK_LPLL]		= &lpll_clk.common.hw,
		[CLK_LPLL_409M6]	= &lpll_409m6.hw,
		[CLK_LPLL_245M76]	= &lpll_245m76.hw,
		[CLK_GPLL]		= &gpll_clk.common.hw,
		[CLK_ISPPLL]		= &isppll_clk.common.hw,
		[CLK_ISPPLL_468M]	= &isppll_468m.hw,

	},
	.num	= CLK_PLL_NUM,
};

static const struct sprd_clk_desc sc9832e_pll_desc = {
	.clk_clks	= sc9832e_pll_clks,
	.num_clk_clks	= ARRAY_SIZE(sc9832e_pll_clks),
	.hw_clks        = &sc9832e_pll_hws,
};

static const struct clk_bit_field f_dpll[PLL_FACT_MAX] = {
	{ .shift = 0,	.width = 0 },	/* lock_done	*/
	{ .shift = 9,	.width = 1 },	/* div_s	*/
	{ .shift = 10,	.width = 1 },	/* mod_en	*/
	{ .shift = 11,	.width = 1 },	/* sdm_en	*/
	{ .shift = 0,	.width = 0 },	/* refin	*/
	{ .shift = 15,	.width = 2 },	/* ibias	*/
	{ .shift = 17,	.width = 11 },	/* n		*/
	{ .shift = 55,	.width = 6 },	/* nint		*/
	{ .shift = 32,	.width = 23},	/* kint		*/
	{ .shift = 0,	.width = 0 },	/* prediv	*/
	{ .shift = 0,	.width = 0 },	/* postdiv	*/
};
static SPRD_PLL_WITH_ITABLE_1K(dpll_clk, "dpll", "dpll-gate", 0x0,
				   2, ftable, f_dpll, 240);

static struct sprd_clk_common *sc9832e_dpll_clks[] = {
	/* address base is 0x403d0000 */
	&dpll_clk.common,

};

static struct clk_hw_onecell_data sc9832e_dpll_hws = {
	.hws	= {
		[CLK_DPLL]	= &dpll_clk.common.hw,

	},
	.num	= CLK_DPLL_NUM,
};

static const struct sprd_clk_desc sc9832e_dpll_desc = {
	.clk_clks	= sc9832e_dpll_clks,
	.num_clk_clks	= ARRAY_SIZE(sc9832e_dpll_clks),
	.hw_clks        = &sc9832e_dpll_hws,
};

#define f_mpll f_twpll
static SPRD_PLL_WITH_ITABLE_1K(mpll_clk, "mpll", "mpll-gate", 0x0,
				2, ftable, f_mpll, 240);

static struct sprd_clk_common *sc9832e_mpll_clks[] = {
	/* address base is 0x403f0000 */
	&mpll_clk.common,

};

static struct clk_hw_onecell_data sc9832e_mpll_hws = {
	.hws	= {
		[CLK_MPLL]	= &mpll_clk.common.hw,

	},
	.num	= CLK_MPLL_NUM,
};

static const struct sprd_clk_desc sc9832e_mpll_desc = {
	.clk_clks	= sc9832e_mpll_clks,
	.num_clk_clks	= ARRAY_SIZE(sc9832e_mpll_clks),
	.hw_clks        = &sc9832e_mpll_hws,
};

static SPRD_SC_GATE_CLK(audio_gate,	"audio-gate",	"ext-26m", 0x8,
		     0x1000, BIT(8), CLK_IGNORE_UNUSED, 0);

static const struct clk_bit_field f_rpll[PLL_FACT_MAX] = {
	{ .shift = 0,	.width = 0 },	/* lock_done	*/
	{ .shift = 3,	.width = 1 },	/* div_s	*/
	{ .shift = 4,	.width = 1 },	/* mod_en	*/
	{ .shift = 5,	.width = 1 },	/* sdm_en	*/
	{ .shift = 0,	.width = 0 },	/* refin	*/
	{ .shift = 9,	.width = 2 },	/* ibias	*/
	{ .shift = 11,	.width = 11 },	/* n		*/
	{ .shift = 55,	.width = 6 },	/* nint		*/
	{ .shift = 32,	.width = 23},	/* kint		*/
	{ .shift = 0,	.width = 0 },	/* prediv	*/
	{ .shift = 0,	.width = 0 },	/* postdiv	*/
};
static SPRD_PLL_WITH_ITABLE_1K(rpll_clk, "rpll", "ext-26m", 0x14,
				   2, ftable, f_rpll, 240);

static SPRD_SC_GATE_CLK(rpll_d1_en,	"rpll-d1-en",	"rpll", 0x1c,
		     0x1000, BIT(8), CLK_IGNORE_UNUSED, 0);

static CLK_FIXED_FACTOR(rpll_390m, "rpll-390m", "rpll-d1-en", 2, 1, 0);
static CLK_FIXED_FACTOR(rpll_260m, "rpll-260m", "rpll", 3, 1, 0);
static CLK_FIXED_FACTOR(rpll_195m, "rpll-195m", "rpll", 4, 1, 0);
static CLK_FIXED_FACTOR(rpll_26m, "rpll-26m", "rpll", 30, 1, 0);

static struct sprd_clk_common *sc9832e_rpll_clks[] = {
	/* address base is 0x40410000 */
	&audio_gate.common,
	&rpll_clk.common,
	&rpll_d1_en.common,
};

static struct clk_hw_onecell_data sc9832e_rpll_hws = {
	.hws	= {
		[CLK_AUDIO_GATE]	= &audio_gate.common.hw,
		[CLK_RPLL]		= &rpll_clk.common.hw,
		[CLK_RPLL_D1_EN]	= &rpll_d1_en.common.hw,
		[CLK_RPLL_390M]		= &rpll_390m.hw,
		[CLK_RPLL_260M]		= &rpll_260m.hw,
		[CLK_RPLL_195M]		= &rpll_195m.hw,
		[CLK_RPLL_26M]		= &rpll_26m.hw,
	},
	.num	= CLK_RPLL_NUM,
};

static const struct sprd_clk_desc sc9832e_rpll_desc = {
	.clk_clks	= sc9832e_rpll_clks,
	.num_clk_clks	= ARRAY_SIZE(sc9832e_rpll_clks),
	.hw_clks        = &sc9832e_rpll_hws,
};

#define SC9832E_MUX_FLAG	\
	(CLK_GET_RATE_NOCACHE | CLK_SET_RATE_NO_REPARENT)

static const char * const ap_apb_parents[] = { "ext-26m", "twpll-64m",
					       "twpll-96m", "twpll-128m" };
static SPRD_MUX_CLK(ap_apb, "ap-apb", ap_apb_parents, 0x20,
			0, 2, SC9832E_MUX_FLAG);

static const char * const nandc_ecc_parents[] = {	"ext-26m",	"twpll-256m",
						"twpll-307m2"};
static SPRD_COMP_CLK(nandc_ecc,	"nandc-ecc",	nandc_ecc_parents, 0x24,
		     0, 2, 8, 3, 0);

static const char * const otg_ref_parents[] = { "twpll-12m", "twpll-24m" };
static SPRD_MUX_CLK(otg_ref, "otg-ref", otg_ref_parents, 0x28,
			0, 1, SC9832E_MUX_FLAG);

static SPRD_GATE_CLK(otg_utmi, "otg-utmi", "ap-apb", 0x2c,
		     BIT(16), 0, 0);

static const char * const uart_parents[] = {	"ext-26m",	"twpll-48m",
						"twpll-51m2",	"twpll-96m" };
static SPRD_COMP_CLK(uart1_clk,	"uart1",	uart_parents, 0x30,
		     0, 2, 8, 3, 0);

static const char * const i2c_parents[] = { "ext-26m", "twpll-48m",
					    "twpll-51m2", "twpll-153m6" };
static SPRD_COMP_CLK(i2c0_clk,	"i2c0", i2c_parents, 0x34,
		     0, 2, 8, 3, 0);
static SPRD_COMP_CLK(i2c1_clk,	"i2c1", i2c_parents, 0x38,
		     0, 2, 8, 3, 0);
static SPRD_COMP_CLK(i2c2_clk,	"i2c2", i2c_parents, 0x3c,
		     0, 2, 8, 3, 0);
static SPRD_COMP_CLK(i2c3_clk,	"i2c3", i2c_parents, 0x40,
		     0, 2, 8, 3, 0);
static SPRD_COMP_CLK(i2c4_clk,	"i2c4", i2c_parents, 0x44,
		     0, 2, 8, 3, 0);

static const char * const spi_parents[] = {	"ext-26m",	"twpll-128m",
						"twpll-153m6",	"twpll-192m" };
static SPRD_COMP_CLK(spi0_clk,	"spi0",	spi_parents, 0x48,
		     0, 2, 8, 3, 0);
static SPRD_COMP_CLK(spi2_clk,	"spi2",	spi_parents, 0x4c,
		     0, 2, 8, 3, 0);
static SPRD_COMP_CLK(hs_spi_clk,	"hs_spi",	spi_parents, 0x50,
		     0, 2, 8, 3, 0);

static const char * const iis_parents[] = { "ext-26m",
					    "twpll-128m",
					    "twpll-153m6" };
static SPRD_COMP_CLK(iis0_clk,	"iis0",	iis_parents, 0x54,
		     0, 2, 8, 3, 0);

static const char * const ce_parents[] = { "ext-26m", "twpll-153m6",
					   "twpll-170m6", "rpll-195m",
					   "twpll-219m4", "lpll-245m76",
					   "rpll-260m", "twpll-307m2",
					   "rpll-390m" };
static SPRD_MUX_CLK(ce_clk, "ce", ce_parents, 0x58,
			0, 2, SC9832E_MUX_FLAG);


static const char * const nandc_2x_parents[] = { "ext-26m", "twpll-48m",
					    "twpll-51m2", "twpll-153m6" };
static SPRD_COMP_CLK(nandc_2x_clk,	"nandc-2x", nandc_2x_parents, 0x78,
		     0, 4, 8, 4, 0);


static const char * const sdio_parents[] = { "ext-1m", "ext-26m",
					     "twpll-307m2", "twpll-384m",
					     "rpll-390m", "lpll-409m6" };
static SPRD_MUX_CLK(sdio0_2x_clk, "sdio0-2x", sdio_parents, 0x80,
			0, 3, SC9832E_MUX_FLAG);
static SPRD_MUX_CLK(sdio1_2x_clk, "sdio1-2x", sdio_parents, 0x88,
			0, 3, SC9832E_MUX_FLAG);
static SPRD_MUX_CLK(emmc_2x_clk, "emmc-2x", sdio_parents, 0x90,
			0, 3, SC9832E_MUX_FLAG);

static const char * const vsp_parents[] = {	"twpll-76m8",	"twpll-128m",
						"twpll-256m",	"twpll-307m2" };
static SPRD_MUX_CLK(vsp_clk, "vsp", vsp_parents, 0x98,
			0, 2, SC9832E_MUX_FLAG);


static const char * const gsp_parents[] = {	"twpll-153m6",	"twpll-192m",
						"twpll-256m",	"twpll-384m" };
static SPRD_MUX_CLK(gsp_clk, "gsp", gsp_parents, 0x9c,
			0, 2, SC9832E_MUX_FLAG);
static SPRD_MUX_CLK(dispc0_clk, "dispc0", gsp_parents, 0xa0,
			0, 2, SC9832E_MUX_FLAG);

static const char * const dispc_parents[] = {	"twpll-96m",	"twpll-128m",
						"twpll-153m6" };
static SPRD_COMP_CLK(dispc0_dpi, "dispc0-dpi", dispc_parents,	0xa4,
		     0, 2, 8, 4, 0);

static SPRD_GATE_CLK(dsi_rxesc, "dsi-rxesc", "ap-apb", 0xa8,
		     BIT(16), 0, 0);

static SPRD_GATE_CLK(dsi_lanebyte, "dsi-lanebyte", "ap-apb", 0xac,
		     BIT(16), 0, 0);

static struct sprd_clk_common *sc9832e_ap_clks[] = {
	/* address base is 0x21500000 */
	&ap_apb.common,
	&nandc_ecc.common,
	&otg_ref.common,
	&otg_utmi.common,
	&uart1_clk.common,
	&i2c0_clk.common,
	&i2c1_clk.common,
	&i2c2_clk.common,
	&i2c3_clk.common,
	&i2c4_clk.common,
	&spi0_clk.common,
	&spi2_clk.common,
	&hs_spi_clk.common,
	&iis0_clk.common,
	&ce_clk.common,
	&nandc_2x_clk.common,
	&sdio0_2x_clk.common,
	&sdio1_2x_clk.common,
	&emmc_2x_clk.common,
	&vsp_clk.common,
	&gsp_clk.common,
	&dispc0_clk.common,
	&dispc0_dpi.common,
	&dsi_rxesc.common,
	&dsi_lanebyte.common,
};

static struct clk_hw_onecell_data sc9832e_ap_clk_hws = {
	.hws	= {
		[CLK_AP_APB]	= &ap_apb.common.hw,
		[CLK_NANDC_ECC]	= &nandc_ecc.common.hw,
		[CLK_OTG_REF]	= &otg_ref.common.hw,
		[CLK_OTG_UTMI]	= &otg_utmi.common.hw,
		[CLK_UART1]	= &uart1_clk.common.hw,
		[CLK_I2C0]	= &i2c0_clk.common.hw,
		[CLK_I2C1]	= &i2c1_clk.common.hw,
		[CLK_I2C2]	= &i2c2_clk.common.hw,
		[CLK_I2C3]	= &i2c3_clk.common.hw,
		[CLK_I2C4]	= &i2c4_clk.common.hw,
		[CLK_SPI0]	= &spi0_clk.common.hw,
		[CLK_SPI2]	= &spi2_clk.common.hw,
		[CLK_HS_SPI]	= &hs_spi_clk.common.hw,
		[CLK_IIS0]	= &iis0_clk.common.hw,
		[CLK_CE]	= &ce_clk.common.hw,
		[CLK_NANDC_2X]	= &nandc_2x_clk.common.hw,
		[CLK_SDIO0_2X]	= &sdio0_2x_clk.common.hw,
		[CLK_SDIO1_2X]	= &sdio1_2x_clk.common.hw,
		[CLK_EMMC_2X]	= &emmc_2x_clk.common.hw,
		[CLK_VSP]	= &vsp_clk.common.hw,
		[CLK_GSP]	= &gsp_clk.common.hw,
		[CLK_DISPC0]	= &dispc0_clk.common.hw,
		[CLK_DISPC0_DPI]	= &dispc0_dpi.common.hw,
		[CLK_DSI_RXESC]		= &dsi_rxesc.common.hw,
		[CLK_DSI_LANEBYTE]	= &dsi_lanebyte.common.hw,
	},
	.num	= CLK_AP_CLK_NUM,
};

static const struct sprd_clk_desc sc9832e_ap_clk_desc = {
	.clk_clks	= sc9832e_ap_clks,
	.num_clk_clks	= ARRAY_SIZE(sc9832e_ap_clks),
	.hw_clks	= &sc9832e_ap_clk_hws,
};

static const char * const aon_apb_parents[] = { "ext-26m",
						"twpll-38m4",
						"twpll-51m2" };
static SPRD_COMP_CLK(aon_apb, "aon-apb", aon_apb_parents, 0x220,
		     0, 2, 8, 2, 0);

static const char * const adi_parents[] = { "ext-26m", "twpll-38m4",
					    "twpll-51m2" };
static SPRD_MUX_CLK(adi_clk,	"adi",	adi_parents, 0x224,
		    0, 2, SC9832E_MUX_FLAG);

static const char * const pwm_parents[] = { "ext-32k", "ext-26m",
					    "rpll-26m", "twpll-48m" };
static SPRD_MUX_CLK(pwm0_clk,	"pwm0",	pwm_parents, 0x238,
		    0, 2, SC9832E_MUX_FLAG);
static SPRD_MUX_CLK(pwm1_clk,	"pwm1",	pwm_parents, 0x23c,
		    0, 2, SC9832E_MUX_FLAG);
static SPRD_MUX_CLK(pwm2_clk,	"pwm2",	pwm_parents, 0x240,
		    0, 2, SC9832E_MUX_FLAG);
static SPRD_MUX_CLK(pwm3_clk,	"pwm3",	pwm_parents, 0x244,
		    0, 2, SC9832E_MUX_FLAG);

static const char * const thm_parents[] = { "ext-32k", "ext-250k" };
static SPRD_MUX_CLK(thm0_clk,	"thm0",	thm_parents, 0x258,
		    0, 1, SC9832E_MUX_FLAG);
static SPRD_MUX_CLK(thm1_clk,	"thm1",	thm_parents, 0x25c,
		    0, 1, SC9832E_MUX_FLAG);

static const char * const audif_parents[] = { "ext-26m", "twpll-38m4",
					      "twpll-51m2" };
static SPRD_MUX_CLK(audif_clk,	"audif", audif_parents, 0x264,
		    0, 2, SC9832E_MUX_FLAG);


static SPRD_GATE_CLK(aud_iis_da0, "aud-iis-da0", "ap-apb", 0x26c,
		     BIT(16), 0, 0);
static SPRD_GATE_CLK(aud_iis_ad0, "aud-iis-ad0", "ap-apb", 0x270,
		     BIT(16), 0, 0);

static const char * const ca53_dap_parents[] = { "ext-26m", "twpll-76m8",
						 "twpll-128m",	"twpll-153m6" };
static SPRD_MUX_CLK(ca53_dap, "ca53-dap", ca53_dap_parents, 0x274,
		    0, 2, SC9832E_MUX_FLAG);

static SPRD_GATE_CLK(ca53_dmtck, "ca53-dmtck", "ap-apb", 0x278,
		     BIT(16), 0, 0);

static const char * const ca53_ts_parents[] = {	"ext-32k", "ext-26m",
						"clk-twpll-128m",
						"clk-twpll-153m6" };
static SPRD_MUX_CLK(ca53_ts, "ca53-ts", ca53_ts_parents, 0x27c,
		    0, 2, SC9832E_MUX_FLAG);

static SPRD_GATE_CLK(djtag_tck, "djtag-tck", "ap-apb", 0x280,
		     BIT(16), 0, 0);

static const char * const emc_ref_parents[] = {	"ext-6m5", "ext-13m", "ext-26m" };
static SPRD_MUX_CLK(emc_ref, "emc-ref", emc_ref_parents, 0x28c,
		    0, 2, SC9832E_MUX_FLAG);

static const char * const cssys_parents[] = { "ext-26m", "twpll-96m",
					      "twpll-128m", "twpll-153m6",
					      "twpll-256m" };
static SPRD_COMP_CLK(cssys_clk, "cssys", cssys_parents, 0x290,
		     0, 3, 8, 2, 0);

static const char * const tmr_parents[] = { "ext-32k", "ext-4m3" };
static SPRD_MUX_CLK(tmr_clk, "tmr", tmr_parents, 0x298,
		    0, 1, SC9832E_MUX_FLAG);

static SPRD_GATE_CLK(dsi_test, "dsi-test", "ap-apb", 0x2a0,
		     BIT(16), 0, 0);

static const char * const sdphy_apb_parents[] = { "ext-26m", "twpll-48m" };
static SPRD_MUX_CLK(sdphy_apb, "sdphy-apb", sdphy_apb_parents, 0x2b8,
		    0, 1, SC9832E_MUX_FLAG);
static SPRD_COMP_CLK(aio_apb, "aio-apb", sdphy_apb_parents, 0x2c4,
		     0, 1, 8, 2, 0);

static SPRD_GATE_CLK(dtck_hw, "dtck-hw", "ap-apb", 0x2c8,
		     BIT(16), 0, 0);

static const char * const ap_mm_parents[] = { "ext-26m", "twpll-96m",
					      "twpll-128m" };
static SPRD_COMP_CLK(ap_mm, "ap-mm", ap_mm_parents, 0x2cc,
		     0, 2, 8, 2, 0);

static const char * const ap_axi_parents[] = { "ext-26m", "twpll-76m8",
					       "twpll-128m", "twpll-256m" };
static SPRD_MUX_CLK(ap_axi, "ap-axi", ap_axi_parents, 0x2d0,
		    0, 2, SC9832E_MUX_FLAG);

static const char * const nic_gpu_parents[] = { "twpll-256m", "twpll-307m2",
						"twpll-384m", "twpll-512m",
						"gpll"};
static SPRD_COMP_CLK(nic_gpu, "nic-gpu", nic_gpu_parents, 0x2d8,
		     0, 3, 8, 3, 0);

static const char * const mm_isp_parents[] = { "twpll-128m", "twpll-256m",
					       "twpll-307m2", "twpll-384m",
					       "isppll-468m" };
static SPRD_MUX_CLK(mm_isp, "mm-isp", mm_isp_parents, 0x2dc,
		    0, 3, SC9832E_MUX_FLAG);

static struct sprd_clk_common *sc9832e_aon_prediv[] = {
	/* address base is 0x402d0000 */
	&aon_apb.common,
	&adi_clk.common,
	&pwm0_clk.common,
	&pwm1_clk.common,
	&pwm2_clk.common,
	&pwm3_clk.common,
	&thm0_clk.common,
	&thm1_clk.common,
	&audif_clk.common,
	&aud_iis_da0.common,
	&aud_iis_ad0.common,
	&ca53_dap.common,
	&ca53_dmtck.common,
	&ca53_ts.common,
	&djtag_tck.common,
	&emc_ref.common,
	&cssys_clk.common,
	&tmr_clk.common,
	&dsi_test.common,
	&sdphy_apb.common,
	&aio_apb.common,
	&dtck_hw.common,
	&ap_mm.common,
	&ap_axi.common,
	&nic_gpu.common,
	&mm_isp.common,
};

static struct clk_hw_onecell_data sc9832e_aon_prediv_hws = {
	.hws	= {
		[CLK_AON_APB]		= &aon_apb.common.hw,
		[CLK_ADI]		= &adi_clk.common.hw,
		[CLK_PWM0]		= &pwm0_clk.common.hw,
		[CLK_PWM1]		= &pwm1_clk.common.hw,
		[CLK_PWM2]		= &pwm2_clk.common.hw,
		[CLK_PWM3]		= &pwm3_clk.common.hw,
		[CLK_THM0]		= &thm0_clk.common.hw,
		[CLK_THM1]		= &thm1_clk.common.hw,
		[CLK_AUDIF]		= &audif_clk.common.hw,
		[CLK_AUD_IIS_DA0]	= &aud_iis_da0.common.hw,
		[CLK_AUD_IIS_AD0]	= &aud_iis_ad0.common.hw,
		[CLK_CA53_DAP]		= &ca53_dap.common.hw,
		[CLK_CA53_DMTCK]	= &ca53_dmtck.common.hw,
		[CLK_CA53_TS]		= &ca53_ts.common.hw,
		[CLK_DJTAG_TCK]		= &djtag_tck.common.hw,
		[CLK_EMC_REF]		= &emc_ref.common.hw,
		[CLK_CSSYS]		= &cssys_clk.common.hw,
		[CLK_TMR]		= &tmr_clk.common.hw,
		[CLK_DSI_TEST]		= &dsi_test.common.hw,
		[CLK_SDPHY_APB]		= &sdphy_apb.common.hw,
		[CLK_AIO_APB]		= &aio_apb.common.hw,
		[CLK_DTCK_HW]		= &dtck_hw.common.hw,
		[CLK_AP_MM]		= &ap_mm.common.hw,
		[CLK_AP_AXI]		= &ap_axi.common.hw,
		[CLK_NIC_GPU]		= &nic_gpu.common.hw,
		[CLK_MM_ISP]		= &mm_isp.common.hw,
	},
	.num	= CLK_AON_PREDIV_NUM,
};

static const struct sprd_clk_desc sc9832e_aon_prediv_desc = {
	.clk_clks	= sc9832e_aon_prediv,
	.num_clk_clks	= ARRAY_SIZE(sc9832e_aon_prediv),
	.hw_clks	= &sc9832e_aon_prediv_hws,
};


static SPRD_SC_GATE_CLK(dsi_eb, "dsi-eb", "ap-axi", 0x0, 0x1000,
			BIT(0), 0, 0);
static SPRD_SC_GATE_CLK(dispc_eb, "dispc-eb", "ap-axi", 0x0, 0x1000,
			BIT(1), 0, 0);
static SPRD_SC_GATE_CLK(vsp_eb, "vsp-eb", "ap-axi", 0x0, 0x1000,
			BIT(2), 0, 0);
static SPRD_SC_GATE_CLK(gsp_eb, "gsp-eb", "ap-axi", 0x0, 0x1000,
			BIT(3), 0, 0);
static SPRD_SC_GATE_CLK(otg_eb, "otg-eb", "ap-axi", 0x0, 0x1000,
			BIT(4), 0, 0);
static SPRD_SC_GATE_CLK(dma_pub_eb, "dma-pub-eb", "ap-axi", 0x0, 0x1000,
			BIT(5), 0, 0);
static SPRD_SC_GATE_CLK(ce_pub_eb, "ce-pub-eb", "ap-axi", 0x0, 0x1000,
			BIT(6), 0, 0);
static SPRD_SC_GATE_CLK(ahb_ckg_eb, "ahb-ckg-eb", "ap-axi", 0x0, 0x1000,
			BIT(7), 0, 0);
static SPRD_SC_GATE_CLK(sdio0_eb, "sdio0-eb", "ap-axi", 0x0, 0x1000,
			BIT(8), 0, 0);
static SPRD_SC_GATE_CLK(sdio1_eb, "sdio1-eb", "ap-axi", 0x0, 0x1000,
			BIT(9), 0, 0);
static SPRD_SC_GATE_CLK(nandc_eb, "nandc-eb", "ap-axi", 0x0, 0x1000,
			BIT(10), 0, 0);
static SPRD_SC_GATE_CLK(emmc_eb, "emmc-eb", "ap-axi", 0x0, 0x1000,
			BIT(11), 0, 0);
static SPRD_SC_GATE_CLK(spinlock_eb, "spinlock-eb", "ap-axi", 0x0, 0x1000,
			BIT(13), 0, 0);
static SPRD_SC_GATE_CLK(ce_efuse_eb, "ce-efuse-eb", "ap-axi", 0x0, 0x1000,
			BIT(23), 0, 0);
static SPRD_SC_GATE_CLK(emmc_32k_eb, "emmc-32k-eb", "ap-axi", 0x0, 0x1000,
			BIT(27), 0, 0);
static SPRD_SC_GATE_CLK(sdio0_32k_eb, "sdio0-32k-eb", "ap-axi", 0x0, 0x1000,
			BIT(28), 0, 0);
static SPRD_SC_GATE_CLK(sdio1_32k_eb, "sdio1-32k-eb", "ap-axi", 0x0, 0x1000,
			BIT(29), 0, 0);

static const char * const mcu_parents[] = { "ext-26m", "twpll-512m",
					    "twpll-768m", "mpll" };
static SPRD_COMP_CLK(mcu_clk, "mcu", mcu_parents, 0x54,
		     0, 3, 8, 3, 0);

static struct sprd_clk_common *sc9832e_apahb_gate[] = {
	/* address base is 0x20e00000 */
	&dsi_eb.common,
	&dispc_eb.common,
	&vsp_eb.common,
	&gsp_eb.common,
	&otg_eb.common,
	&dma_pub_eb.common,
	&ce_pub_eb.common,
	&ahb_ckg_eb.common,
	&sdio0_eb.common,
	&sdio1_eb.common,
	&nandc_eb.common,
	&emmc_eb.common,
	&spinlock_eb.common,
	&ce_efuse_eb.common,
	&emmc_32k_eb.common,
	&sdio0_32k_eb.common,
	&sdio1_32k_eb.common,
	&mcu_clk.common,
};

static struct clk_hw_onecell_data sc9832e_apahb_gate_hws = {
	.hws	= {
		[CLK_DSI_EB]		= &dsi_eb.common.hw,
		[DISPC_EB]		= &dispc_eb.common.hw,
		[VSP_EB]		= &vsp_eb.common.hw,
		[GSP_EB]		= &gsp_eb.common.hw,
		[OTG_EB]		= &otg_eb.common.hw,
		[DMA_PUB_EB]		= &dma_pub_eb.common.hw,
		[CE_PUB_EB]		= &ce_pub_eb.common.hw,
		[AHB_CKG_EB]		= &ahb_ckg_eb.common.hw,
		[SDIO0_EB]		= &sdio0_eb.common.hw,
		[SDIO1_EB]		= &sdio1_eb.common.hw,
		[NANDC_EB]		= &nandc_eb.common.hw,
		[EMMC_EB]		= &emmc_eb.common.hw,
		[SPINLOCK_EB]		= &spinlock_eb.common.hw,
		[CE_EFUSE_EB]		= &ce_efuse_eb.common.hw,
		[EMMC_32K_EB]		= &emmc_32k_eb.common.hw,
		[SDIO0_32K_EB]		= &sdio0_32k_eb.common.hw,
		[SDIO1_32K_EB]		= &sdio1_32k_eb.common.hw,
		[SDIO1_MCU]		= &mcu_clk.common.hw,
	},
	.num	= CLK_APAHB_GATE_NUM,
};

static const struct sprd_clk_desc sc9832e_apahb_gate_desc = {
	.clk_clks	= sc9832e_apahb_gate,
	.num_clk_clks	= ARRAY_SIZE(sc9832e_apahb_gate),
	.hw_clks	= &sc9832e_apahb_gate_hws,
};

static const struct of_device_id sprd_sc9832e_clk_ids[] = {
	{ .compatible = "sprd,sc9832e-pmu-gate",	/* 0x402b0000 */
	  .data = &sc9832e_pmu_gate_desc },
	{ .compatible = "sprd,sc9832e-pll",	/* 0x403c0000 */
	  .data = &sc9832e_pll_desc },
	{ .compatible = "sprd,sc9832e-dpll",	/* 0x403d0000 */
	  .data = &sc9832e_dpll_desc },
	{ .compatible = "sprd,sc9832e-mpll",	/* 0x403f0000 */
	  .data = &sc9832e_mpll_desc },
	{ .compatible = "sprd,sc9832e-rpll",	/* 0x40410000 */
	  .data = &sc9832e_rpll_desc },
	{ .compatible = "sprd,sc9832e-ap-clks",		/* 0x21500000 */
	  .data = &sc9832e_ap_clk_desc },
	{ .compatible = "sprd,sc9832e-aon-prediv",	/* 0x402d0000 */
	  .data = &sc9832e_aon_prediv_desc },
	{ .compatible = "sprd,sc9832e-apahb-gate",		/* 0x20e00000 */
	  .data = &sc9832e_apahb_gate_desc },
	{ }
};
MODULE_DEVICE_TABLE(of, sprd_sc9832e_clk_ids);

static int sc9832e_clk_probe(struct platform_device *pdev)
{
	const struct of_device_id *match;
	const struct sprd_clk_desc *desc;
	int ret;

	match = of_match_node(sprd_sc9832e_clk_ids, pdev->dev.of_node);
	if (!match) {
		pr_err("%s: of_match_node() failed", __func__);
		return -ENODEV;
	}

	desc = match->data;
	ret = sprd_clk_regmap_init(pdev, desc);
	if (ret)
		return ret;

	return sprd_clk_probe(&pdev->dev, desc->hw_clks);
}

static struct platform_driver sc9832e_clk_driver = {
	.probe	= sc9832e_clk_probe,
	.driver	= {
		.name	= "sc9832e-clk",
		.of_match_table	= sprd_sc9832e_clk_ids,
	},
};
module_platform_driver(sc9832e_clk_driver);

MODULE_DESCRIPTION("Spreadtrum SC9832E Clock Driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:sc9832e-clk");
