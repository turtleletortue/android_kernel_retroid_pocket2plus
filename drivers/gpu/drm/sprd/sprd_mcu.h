#ifndef _SPRD_MCU_DRV_H_
#define _SPRD_MCU_DRV_H_

#include <linux/delay.h>
#include <linux/of_device.h>

enum SPRD_SENSOR_REGULATOR_ID_E {
	SENSOR_REGULATOR_VDDIO_E,
	SENSOR_REGULATOR_CAMAVDD_ID_E,
	SENSOR_REGULATOR_CAMDVDD_ID_E,
	SENSOR_REGULATOR_CAMMOT_ID_E,
	SENSOR_REGULATOR_ID_MAX
};

enum SPRD_SENSOR_ID_E {
	SPRD_SENSOR_MAIN_ID_E,
	SPRD_SENSOR_SUB_ID_E,
	SPRD_SENSOR_MAIN2_ID_E,
	SPRD_SENSOR_SUB2_ID_E,
	SPRD_SENSOR_MAIN3_ID_E,
	SPRD_SENSOR_SUB3_ID_E,
	SPRD_SENSOR_ID_MAX
};

struct sprd_sensor_dev_info_tag {
	struct mutex sync_lock;
	struct mutex set_voltage_lock;
	atomic_t users;
	struct clk *sensor_clk;
	struct clk *sensor_clk_default;
	unsigned long sensor_clk_default_rate;
	struct clk *ccir_eb;
	struct clk *sensor_eb;
	struct regulator *regulator_supply[SENSOR_REGULATOR_ID_MAX];
	struct i2c_client *i2c_info;
	struct i2c_client *vcm_i2c_client;
	unsigned int power_on_count[SENSOR_REGULATOR_ID_MAX];

	int sensor_id;
	int attch_dcam_id;
	int mclk_freq;
	struct device_node *dev_node;
};

#define SPRD_MCU_MINOR		MISC_DYNAMIC_MINOR
#define SPRD_MCU_DEVICE_NAME	"sprd_mcu"
#define SPRD_MCU_DRIVER_NAME	"sprd_mcu"

#define SPRD_MCU_VDD_3300MV	3300000
#define SPRD_MCU_VDD_CLOSED	1200000

#endif