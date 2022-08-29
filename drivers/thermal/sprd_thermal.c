// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2018 Spreadtrum Communications Inc.

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/nvmem-consumer.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/thermal.h>
#include <linux/slab.h>

#define SPRD_THM_CTL			0x0
#define SPRD_THM_INT_EN			0x4
#define SPRD_THM_INT_STS		0x8
#define SPRD_THM_INT_RAW_STS		0xc
#define SPRD_THM_DET_PERIOD		0x10
#define SPRD_THM_INT_CLR		0x14
#define SPRD_THM_INT_CLR_ST		0x18
#define SPRD_THM0_OVERHEAT_HOT_THRES	0x2c
#define SPRD_THM1_OVERHEAT_HOT_THRES	0x30
#define SPRD_THM2_OVERHEAT_HOT_THRES	0x34
#define SPRD_THM3_OVERHEAT_HOT_THRES	0x38
#define SPRD_THM4_OVERHEAT_HOT_THRES	0x3c
#define SPRD_THM5_OVERHEAT_HOT_THRES	0x40
#define SPRD_THM6_OVERHEAT_HOT_THRES	0x44
#define SPRD_THM7_OVERHEAT_HOT_THRES	0x48
#define SPRD_THM_MON_PERIOD		0x4c
#define SPRD_THM_MON_CTL		0x50
#define SPRD_THM_INTERNAL_STS1		0x54
#define SPRD_THM_SENSOR0_TEMP		0x5c
#define SPRD_THM_SENSOR1_TEMP		0x60
#define SPRD_THM_SENSOR2_TEMP		0x64
#define SPRD_THM_SENSOR3_TEMP		0x68
#define SPRD_THM_SENSOR4_TEMP		0x6c
#define SPRD_THM_SENSOR5_TEMP		0x70
#define SPRD_THM_SENSOR6_TEMP		0x74
#define SPRD_THM_SENSOR7_TEMP		0x78
#define SPRD_THM_RAW_READ_MSK		0x3ff

/* bits definitions for register THM_CTL */
#define SPRD_THM_SET_RDY_ST		BIT(13)
#define SPRD_THM_SET_RDY		BIT(12)
#define SPRD_SEN7_EN			BIT(9)
#define SPRD_SEN6_EN			BIT(8)
#define SPRD_SEN5_EN			BIT(7)
#define SPRD_SEN4_EN			BIT(6)
#define SPRD_SEN3_EN			BIT(5)
#define SPRD_SEN2_EN			BIT(4)
#define SPRD_SEN1_EN			BIT(3)
#define SPRD_SEN0_EN			BIT(2)
#define SPRD_THM_MON_EN			BIT(1)
#define SPRD_THM_EN			BIT(0)

/* bits definitions for register THM_INT_CTL */
#define SPRD_THM_BIT_INT_EN		BIT(26)
#define SPRD_THM_OVERHEAT_EN		BIT(25)
#define SPRD_SEN7_OVERHEAT_EN		BIT(15)
#define SPRD_SEN6_OVERHEAT_EN		BIT(14)
#define SPRD_SEN5_OVERHEAT_EN		BIT(13)
#define SPRD_SEN4_OVERHEAT_EN		BIT(12)
#define SPRD_SEN3_OVERHEAT_EN		BIT(11)
#define SPRD_SEN2_OVERHEAT_EN		BIT(10)
#define SPRD_SEN1_OVERHEAT_EN		BIT(9)
#define SPRD_SEN0_OVERHEAT_EN		BIT(8)
#define SPRD_SEN7_OVERHEAT_ALARM_EN	BIT(7)
#define SPRD_SEN6_OVERHEAT_ALARM_EN	BIT(6)
#define SPRD_SEN5_OVERHEAT_ALARM_EN	BIT(5)
#define SPRD_SEN4_OVERHEAT_ALARM_EN	BIT(4)
#define SPRD_SEN3_OVERHEAT_ALARM_EN	BIT(3)
#define SPRD_SEN2_OVERHEAT_ALARM_EN	BIT(2)
#define SPRD_SEN1_OVERHEAT_ALARM_EN	BIT(1)
#define SPRD_SEN0_OVERHEAT_ALARM_EN	BIT(0)
#define SPRD_THM_OTP_TRIP_SHIFT		10

/* bits definitions for register SPRD_THM_INTERNAL_STS1 */
#define SPRD_THM_TEMPER_RDY		BIT(0)

#define SPRD_DET_PERIOD			0x800
#define SPRD_DET_PERIOD_MASK		GENMASK(19, 0)
#define SPRD_MON_MODE			0x7
#define SPRD_MON_MODE_MASK		GENMASK(3, 0)
#define SPRD_MON_PERIOD			0x10
#define SPRD_MON_PERIOD_MASK		GENMASK(15, 0)
#define SPRD_OVERHEAT_HOT_THRES_MASK	GENMASK(19, 0)
#define SPRD_INT_CLR			GENMASK(24, 0)

/* thm efuse cal para */
#define SPRD_TEMP_LOW			-40000
#define SPRD_TEMP_HIGH			120000
#define SPRD_OTPTEMP			120000
#define SPRD_HOTTEMP			75000
#define SPRD_RAW_DATA_LOW		0
#define SPRD_RAW_DATA_HIGH		1000
#define SPRD_THM_SEN_NUM		8
#define SPRD_THM_DT_OFFSET		24
#define SPRD_THM_RATION_OFFSET		17
#define SPRD_THM_RATION_SIGN		16

#define SPRD_THM_RDYST_POLLING_TIME	10
#define SPRD_THM_RDYST_TIMEOUT		700
#define SPRD_THM_TEMP_READY_POLL_TIME	10000
#define SPRD_THM_TEMP_READY_TIMEOUT	600000

struct sprd_thermal_sensor {
	struct thermal_zone_device *thmzone_dev;
	struct device *dev;
	struct list_head node;
	void __iomem *base;
	u32 enable;
	u32 overheat_en;
	u32 overheat_alarm_en;
	u32 overheat_hot_thres;
	u32 temp;
	u32 rawdata;
	u32 otp_rawdata;
	u32 hot_rawdata;
	u32 ideal_k;
	u32 ideal_b;
	u32 cal_blk;
	u32 ratio_sign;
	bool ready;
	int cal_slope;
	int cal_offset;
	int lasttemp;
	int phy_sen;
	int id;
};

struct sprd_thermal_data {
	struct clk *clk;
	struct list_head senlist;
	void __iomem *regbase;
	u32 ratio_off;
	u32 ratio_sign;
	const struct sprd_thm_variant_data *var_data;
};

/*
 * Since different sprd thermal series can have different
 * ideal_k and ideal_b, we should save ideal_k and ideal_b
 * in the device data structure.
 */
struct sprd_thm_variant_data {
	u32 ideal_k;
	u32 ideal_b;
};

static const struct sprd_thm_variant_data sharkl5_data = {
	.ideal_k = 262,
	.ideal_b = 66400,
};

static inline void sprd_thm_update_bits(void __iomem *reg, u32 mask, u32 val)
{
	u32 tmp, orig;

	orig = readl(reg);
	tmp = orig & ~mask;
	tmp |= val & mask;
	writel(tmp, reg);
}

static int sprd_thm_cal_read(struct device_node *np, const char *cell_id, u32 *val)
{
	struct nvmem_cell *cell;
	void *buf;
	size_t len;

	cell = of_nvmem_cell_get(np, cell_id);
	if (IS_ERR(cell))
		return PTR_ERR(cell);

	buf = nvmem_cell_read(cell, &len);
	if (IS_ERR(buf)) {
		nvmem_cell_put(cell);
		return PTR_ERR(buf);
	}

	memcpy(val, buf, min(len, sizeof(u32)));

	kfree(buf);
	nvmem_cell_put(cell);
	return 0;
}

static int sprd_thm_sen_efuse_cal(struct device_node *np,
				  struct sprd_thermal_data *thm,
				  struct sprd_thermal_sensor *sen)
{
	int ret;
	/*
	 * According to thermal datasheet calibration offset
	 * default val is 64, ratio val default is 1000.
	 */
	int dt_offset = 64, ratio = 1000;

	ret = sprd_thm_cal_read(np, "sen_delta_cal", &dt_offset);
	if (ret)
		return ret;

	if (thm->ratio_sign == 1)
		ratio = 1000 - thm->ratio_off;
	else
		ratio = 1000 + thm->ratio_off;

	/*
	 * According to the ideal slope K and ideal offset B, combined with
	 * calibration val of thermal from efuse,
	 * then confirm real slope k and offset b.
	 * k_cal =(k * ratio)/1000.
	 * b_cal = b + (dt_offset - 64) * 500.
	 */
	sen->cal_slope = (thm->var_data->ideal_k * ratio) / 1000;
	sen->cal_offset = thm->var_data->ideal_b + (dt_offset - 128) * 250;

	dev_info(sen->dev, "sen id = %d, cal =%d,offset =%d\n", sen->id,
		 sen->cal_slope, sen->cal_offset);
	return 0;
}

static int sprd_rawdata_to_temp_v1(struct sprd_thermal_sensor *sen)
{
	if (sen->rawdata < SPRD_RAW_DATA_LOW)
		sen->rawdata = SPRD_RAW_DATA_LOW;
	else if (sen->rawdata > SPRD_RAW_DATA_HIGH)
		sen->rawdata = SPRD_RAW_DATA_HIGH;

	/*
	 * According to thermal datasheet adc value conversion
	 * temperature formula T_final = k_cal * x - b_cal.
	 */
	return sen->cal_slope * sen->rawdata - sen->cal_offset;
}

static int sprd_temp_to_rawdata_v1(int temp, struct sprd_thermal_sensor *sen)
{
	u32 rawval;

	if (temp < SPRD_TEMP_LOW)
		temp = SPRD_TEMP_LOW;
	else if (temp > SPRD_TEMP_HIGH)
		temp = SPRD_TEMP_HIGH;

	/*
	 * Backstepping temperature convert to adc val
	 * according to the formula T_final = k_cal * x - b_cal.
	 */
	rawval = (temp + sen->cal_offset) / sen->cal_slope;

	return rawval >= SPRD_RAW_DATA_HIGH ? (SPRD_RAW_DATA_HIGH - 1) : rawval;
}

static int sprd_thm_temp_read(void *devdata, int *temp)
{
	struct sprd_thermal_sensor *sen = devdata;
	int sensor_temp;

	sen->rawdata = readl(sen->base + sen->temp);
	sen->rawdata = sen->rawdata & SPRD_THM_RAW_READ_MSK;
	if (sen->ready) {
		sensor_temp = sprd_rawdata_to_temp_v1(sen);
		sen->lasttemp = sensor_temp;
		*temp = sensor_temp;
	} else {
		*temp = sen->lasttemp;
	}

	return 0;
}

static int sprd_thm_poll_ready_status(struct sprd_thermal_data *thm)
{
	u32 thm_ctl_val;
	int ret;

	/* Wait for thm ready status before config thm parameter */
	ret = readl_poll_timeout(thm->regbase + SPRD_THM_CTL,
				 thm_ctl_val,
				 !(thm_ctl_val & SPRD_THM_SET_RDY_ST),
				 SPRD_THM_RDYST_POLLING_TIME,
				 SPRD_THM_RDYST_TIMEOUT);
	if (ret)
		return ret;

	sprd_thm_update_bits(thm->regbase + SPRD_THM_CTL, SPRD_THM_MON_EN,
			     SPRD_THM_MON_EN);
	sprd_thm_update_bits(thm->regbase + SPRD_THM_CTL, SPRD_THM_SET_RDY,
			     SPRD_THM_SET_RDY);
	return ret;
}

static int sprd_thm_wait_temp_ready(struct sprd_thermal_data *thm)
{
	u32 thm_intern_val;

	/* Wait for first temperature data ready before get temperature */
	return readl_poll_timeout(thm->regbase + SPRD_THM_INTERNAL_STS1,
				  thm_intern_val,
				  !(thm_intern_val & SPRD_THM_TEMPER_RDY),
				  SPRD_THM_TEMP_READY_POLL_TIME,
				  SPRD_THM_TEMP_READY_TIMEOUT);
}

static void sprd_thm_sen_threshold_config(struct sprd_thermal_sensor *sen)
{
	sen->otp_rawdata = sprd_temp_to_rawdata_v1(SPRD_OTPTEMP, sen);
	sen->hot_rawdata = sprd_temp_to_rawdata_v1(SPRD_HOTTEMP, sen);
}

static int sprd_thm_sen_config(struct sprd_thermal_sensor *sen)
{
	switch (sen->id) {
	case 0:
		sen->temp = SPRD_THM_SENSOR0_TEMP;
		sen->overheat_hot_thres = SPRD_THM0_OVERHEAT_HOT_THRES;
		sen->enable = SPRD_SEN0_EN;
		sen->overheat_en = SPRD_SEN0_OVERHEAT_EN;
		sen->overheat_alarm_en = SPRD_SEN0_OVERHEAT_ALARM_EN;
		break;
	case 1:
		sen->temp = SPRD_THM_SENSOR1_TEMP;
		sen->overheat_hot_thres = SPRD_THM1_OVERHEAT_HOT_THRES;
		sen->enable = SPRD_SEN1_EN;
		sen->overheat_en = SPRD_SEN1_OVERHEAT_EN;
		sen->overheat_alarm_en = SPRD_SEN1_OVERHEAT_ALARM_EN;
		break;
	case 2:
		sen->temp = SPRD_THM_SENSOR2_TEMP;
		sen->overheat_hot_thres = SPRD_THM2_OVERHEAT_HOT_THRES;
		sen->enable = SPRD_SEN2_EN;
		sen->overheat_en = SPRD_SEN2_OVERHEAT_EN;
		sen->overheat_alarm_en = SPRD_SEN2_OVERHEAT_ALARM_EN;
		break;
	case 3:
		sen->temp = SPRD_THM_SENSOR3_TEMP;
		sen->overheat_hot_thres = SPRD_THM3_OVERHEAT_HOT_THRES;
		sen->enable = SPRD_SEN3_EN;
		sen->overheat_en = SPRD_SEN3_OVERHEAT_EN;
		sen->overheat_alarm_en = SPRD_SEN3_OVERHEAT_ALARM_EN;
		break;
	case 4:
		sen->temp = SPRD_THM_SENSOR4_TEMP;
		sen->overheat_hot_thres = SPRD_THM4_OVERHEAT_HOT_THRES;
		sen->enable = SPRD_SEN4_EN;
		sen->overheat_en = SPRD_SEN4_OVERHEAT_EN;
		sen->overheat_alarm_en = SPRD_SEN4_OVERHEAT_ALARM_EN;
		break;
	case 5:
		sen->temp = SPRD_THM_SENSOR5_TEMP;
		sen->overheat_hot_thres = SPRD_THM5_OVERHEAT_HOT_THRES;
		sen->enable = SPRD_SEN5_EN;
		sen->overheat_en = SPRD_SEN5_OVERHEAT_EN;
		sen->overheat_alarm_en = SPRD_SEN5_OVERHEAT_ALARM_EN;
		break;
	case 6:
		sen->temp = SPRD_THM_SENSOR6_TEMP;
		sen->overheat_hot_thres = SPRD_THM6_OVERHEAT_HOT_THRES;
		sen->enable = SPRD_SEN6_EN;
		sen->overheat_en = SPRD_SEN6_OVERHEAT_EN;
		sen->overheat_alarm_en = SPRD_SEN6_OVERHEAT_ALARM_EN;
		break;
	case 7:
		sen->temp = SPRD_THM_SENSOR7_TEMP;
		sen->overheat_hot_thres = SPRD_THM7_OVERHEAT_HOT_THRES;
		sen->enable = SPRD_SEN7_EN;
		sen->overheat_en = SPRD_SEN7_OVERHEAT_EN;
		sen->overheat_alarm_en = SPRD_SEN7_OVERHEAT_ALARM_EN;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void sprd_thm_para_config(struct sprd_thermal_data *thm)
{
	sprd_thm_update_bits(thm->regbase + SPRD_THM_DET_PERIOD,
			     SPRD_DET_PERIOD_MASK, SPRD_DET_PERIOD);
	sprd_thm_update_bits(thm->regbase + SPRD_THM_MON_CTL,
			     SPRD_MON_MODE_MASK, SPRD_MON_MODE);
	sprd_thm_update_bits(thm->regbase + SPRD_THM_MON_PERIOD,
			     SPRD_MON_PERIOD_MASK, SPRD_MON_PERIOD);
}

static void sprd_thm_sen_init(struct sprd_thermal_data *thm,
				struct sprd_thermal_sensor *sen)
{
	sprd_thm_update_bits(thm->regbase + SPRD_THM_INT_EN,
			     sen->overheat_alarm_en,
			     sen->overheat_alarm_en);
	sprd_thm_update_bits(thm->regbase + sen->overheat_hot_thres,
			     SPRD_OVERHEAT_HOT_THRES_MASK,
			     ((sen->otp_rawdata << SPRD_THM_OTP_TRIP_SHIFT) |
			      sen->hot_rawdata));
	sprd_thm_update_bits(thm->regbase + SPRD_THM_CTL, sen->enable,
			     sen->enable);
}

static int sprd_thm_set_ready(struct sprd_thermal_data *thm)
{
	int ret;

	ret = sprd_thm_poll_ready_status(thm);
	if (ret)
		return ret;

	sprd_thm_update_bits(thm->regbase + SPRD_THM_INT_EN,
			     SPRD_THM_BIT_INT_EN, SPRD_THM_BIT_INT_EN);
	writel(SPRD_INT_CLR, thm->regbase + SPRD_THM_INT_CLR);
	sprd_thm_update_bits(thm->regbase + SPRD_THM_CTL,
			     SPRD_THM_EN, SPRD_THM_EN);
	return 0;
}

static const struct thermal_zone_of_device_ops sprd_thm_ops = {
	.get_temp = sprd_thm_temp_read,
};

static int sprd_thm_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct device_node *sen_child;
	struct sprd_thermal_data *thm;
	struct sprd_thermal_sensor *sen;
	struct sprd_thermal_sensor *temp, *pos;
	struct resource *res;
	const struct sprd_thm_variant_data *pdata;
	int ret;

	pdata = of_device_get_match_data(&pdev->dev);
	if (!pdata) {
		dev_err(&pdev->dev, "No matching driver data found\n");
		return -EINVAL;
	}

	thm = devm_kzalloc(&pdev->dev, sizeof(*thm), GFP_KERNEL);
	if (!thm)
		return -ENOMEM;

	thm->var_data = pdata;
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	thm->regbase = devm_ioremap_resource(&pdev->dev, res);
	if (!thm->regbase)
		return -ENOMEM;

	thm->clk = devm_clk_get(&pdev->dev, "enable");
	if (IS_ERR(thm->clk)) {
		dev_err(&pdev->dev, "get the clock failed\n");
		return PTR_ERR(thm->clk);
	}

	ret = clk_prepare_enable(thm->clk);
	if (ret) {
		dev_err(&pdev->dev, "clock prepare enable failed\n");
		return ret;
	}

	INIT_LIST_HEAD(&thm->senlist);
	sprd_thm_para_config(thm);

	ret = sprd_thm_cal_read(np, "thm_sign_cal", &thm->ratio_sign);
	if (ret)
		goto disable_clk;

	ret = sprd_thm_cal_read(np, "thm_ratio_cal", &thm->ratio_off);
	if (ret)
		goto disable_clk;

	for_each_child_of_node(np, sen_child) {
		sen = devm_kzalloc(&pdev->dev, sizeof(*sen), GFP_KERNEL);
		if (!sen) {
			ret = -ENOMEM;
			goto disable_clk;
		}

		ret = of_property_read_u32(sen_child, "reg", &sen->id);
		if (ret) {
			dev_err(&pdev->dev, "get sensor reg failed");
			goto disable_clk;
		}

		ret = sprd_thm_sen_config(sen);
		if (ret)
			goto disable_clk;

		sen->ready = false;
		sen->base = thm->regbase;
		sen->dev = &pdev->dev;

		ret = sprd_thm_sen_efuse_cal(sen_child, thm, sen);
		if (ret) {
			dev_err(&pdev->dev, "efuse cal analysis failed");
			goto disable_clk;
		}

		sprd_thm_sen_threshold_config(sen);
		sprd_thm_sen_init(thm, sen);

		sen->thmzone_dev =
		    devm_thermal_zone_of_sensor_register(sen->dev, sen->id,
							 sen, &sprd_thm_ops);
		if (IS_ERR_OR_NULL(sen->thmzone_dev)) {
			dev_err(&pdev->dev, "register thermal zone failed %d\n",
				sen->id);
			ret = PTR_ERR(sen->thmzone_dev);
			goto disable_clk;
		}

		list_add_tail(&sen->node, &thm->senlist);
	}

	sprd_thm_set_ready(thm);
	ret = sprd_thm_wait_temp_ready(thm);
	if (ret)
		goto disable_clk;

	list_for_each_entry_safe(pos, temp, &thm->senlist, node)
		pos->ready = true;

	platform_set_drvdata(pdev, thm);
	return 0;

disable_clk:
	clk_disable_unprepare(thm->clk);
	return ret;
}

static int sprd_thm_hw_suspend(struct sprd_thermal_data *thm)
{
	struct sprd_thermal_sensor *sen, *temp;
	int ret;

	list_for_each_entry_safe(sen, temp, &thm->senlist, node) {
		sprd_thm_update_bits(sen->base + SPRD_THM_CTL,
				     sen->enable, 0x0);
	}

	ret = sprd_thm_poll_ready_status(thm);
	sprd_thm_update_bits(thm->regbase + SPRD_THM_CTL,
			     SPRD_THM_EN, 0x0);
	return ret;
}

static int sprd_thm_hw_resume(struct sprd_thermal_data *thm)
{
	struct sprd_thermal_sensor *sen, *temp;
	int ret;

	list_for_each_entry_safe(sen, temp, &thm->senlist, node) {
		sprd_thm_update_bits(thm->regbase + SPRD_THM_CTL,
				     sen->enable, sen->enable);
	}

	ret = sprd_thm_poll_ready_status(thm);
	if (ret)
		return ret;

	writel(SPRD_INT_CLR, thm->regbase + SPRD_THM_INT_CLR);
	sprd_thm_update_bits(thm->regbase + SPRD_THM_CTL,
			     SPRD_THM_EN, SPRD_THM_EN);
	return sprd_thm_wait_temp_ready(thm);
}

static int sprd_thm_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct sprd_thermal_data *thm = dev_get_drvdata(&pdev->dev);
	struct sprd_thermal_sensor *sen, *temp;
	int ret;

	list_for_each_entry_safe(sen, temp, &thm->senlist, node)
		sen->ready = false;

	ret = sprd_thm_hw_suspend(thm);
	clk_disable_unprepare(thm->clk);

	return ret;
}

static int sprd_thm_resume(struct platform_device *pdev)
{
	struct sprd_thermal_data *thm = dev_get_drvdata(&pdev->dev);
	struct sprd_thermal_sensor *sen, *temp;
	int ret;

	ret = clk_prepare_enable(thm->clk);
	if (ret)
		return ret;

	ret = sprd_thm_hw_resume(thm);
	if (ret)
		goto disable_clk;

	list_for_each_entry_safe(sen, temp, &thm->senlist, node)
		sen->ready = true;
	return 0;

disable_clk:
	clk_disable_unprepare(thm->clk);
	return ret;
}

static int sprd_thm_remove(struct platform_device *pdev)
{
	struct sprd_thermal_data *thm = platform_get_drvdata(pdev);
	struct sprd_thermal_sensor *sen, *temp;

	list_for_each_entry_safe(sen, temp, &thm->senlist, node) {
		devm_thermal_zone_of_sensor_unregister(&pdev->dev,
						       sen->thmzone_dev);
	}

	clk_disable_unprepare(thm->clk);

	return 0;
}

static const struct of_device_id thermal_of_match[] = {
	{ .compatible = "sprd,sharkl5-thermal", .data = &sharkl5_data},
	{ .compatible = "sprd,roc1-thermal", .data = &sharkl5_data},
	{ .compatible = "sprd,orca-thermal", .data = &sharkl5_data},
	{ },
};

static struct platform_driver sprd_thermal_driver = {
	.probe = sprd_thm_probe,
	.suspend = sprd_thm_suspend,
	.resume = sprd_thm_resume,
	.remove = sprd_thm_remove,
	.driver = {
		.name = "sprd-thermal",
		.of_match_table = thermal_of_match,
	},
};

module_platform_driver(sprd_thermal_driver);

MODULE_AUTHOR("Freeman Liu <freeman.liu@spreadtrum.com>");
MODULE_DESCRIPTION("Spreadtrum thermal driver");
MODULE_LICENSE("GPL v2");
