/*
 * Copyright (C) 2017 Spreadtrum Communications Inc.
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


#include <linux/mfd/syscon.h>
#include <linux/regmap.h>
#include <linux/of.h>
#include "gsp_interface_sharkl3.h"
#include "../gsp_debug.h"
#include "../gsp_interface.h"


int gsp_interface_sharkl3_parse_dt(struct gsp_interface *intf,
				  struct device_node *node)
{
#if 0
	int status = 0;
	struct gsp_interface_sharkl3 *gsp_interface = NULL;

	gsp_interface = (struct gsp_interface_sharkl3 *)intf;

	gsp_interface->clk_aon_apb_disp_eb = of_clk_get_by_name(node,
		SHARKL3_AON_APB_DISP_EB_NAME);

	if (IS_ERR_OR_NULL(gsp_interface->clk_aon_apb_disp_eb)) {
		GSP_ERR("iread clk_aon_apb_disp_eb  failed\n");
		status = -1;
	}

	return status;
#endif
	return 0;
}

int gsp_interface_sharkl3_init(struct gsp_interface *intf)
{
	return 0;
}

int gsp_interface_sharkl3_deinit(struct gsp_interface *intf)
{
	return 0;
}

int gsp_interface_sharkl3_prepare(struct gsp_interface *intf)
{
	return 0;
#if 0
	int ret = -1;
	struct gsp_interface_sharkl3 *gsp_interface = NULL;

	if (IS_ERR_OR_NULL(intf)) {
		GSP_ERR("interface params error\n");
		return ret;
	}

	gsp_interface = (struct gsp_interface_sharkl3 *)intf;


	ret = clk_prepare_enable(gsp_interface->clk_aon_apb_disp_eb);
	if (ret) {
		GSP_ERR("enable interface[%s] clk_aon_apb_disp_eb failed\n",
			gsp_interface_to_name(intf));
		goto clk_aon_apb_disp_eb_disable;
	}

	goto exit;

clk_aon_apb_disp_eb_disable:
	clk_disable_unprepare(gsp_interface->clk_aon_apb_disp_eb);
	GSP_ERR("interface[%s] prepare ERR !\n",
			  gsp_interface_to_name(intf));

exit:
	GSP_DEBUG("interface[%s] prepare success\n",
			  gsp_interface_to_name(intf));
	return ret;
#endif
}

int gsp_interface_sharkl3_unprepare(struct gsp_interface *intf)
{
#if 0
	struct gsp_interface_sharkl3 *gsp_interface = NULL;

	if (IS_ERR_OR_NULL(intf)) {
		GSP_ERR("interface params error\n");
		return -1;
	}

	gsp_interface = (struct gsp_interface_sharkl3 *)intf;

	clk_disable_unprepare(gsp_interface->clk_aon_apb_disp_eb);

	GSP_DEBUG("interface[%s] unprepare success\n",
		  gsp_interface_to_name(intf));
#endif
	return 0;
}

int gsp_interface_sharkl3_reset(struct gsp_interface *intf)
{
	return 0;
}

void gsp_interface_sharkl3_dump(struct gsp_interface *intf)
{

}
