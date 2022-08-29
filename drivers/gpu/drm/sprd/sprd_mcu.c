#include <linux/clk.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/i2c.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_graph.h>
#include <linux/poll.h>
#include <linux/regulator/consumer.h>
#include <linux/sched.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include "sprd_mcu.h"

static const char *const sprd_sensor_supply_names[] = {
	"vddio",
	"vddcama",
	"vddcamd",
	"vddcammot",
};

static struct sprd_sensor_dev_info_tag *s_sensor_dev_data[SPRD_SENSOR_ID_MAX];

static struct sprd_sensor_dev_info_tag *sprd_sensor_get_dev_context(int sensor_id)
{
	if (sensor_id >= SPRD_SENSOR_ID_MAX || sensor_id < 0) {
		printk("sprd_mcu sensor_id %d error!\n", sensor_id);
		return NULL;
	}

	return s_sensor_dev_data[sensor_id];
}

void sprd_sensor_sync_lock(int sensor_id)
{
	struct sprd_sensor_dev_info_tag *p_dev;

	p_dev = sprd_sensor_get_dev_context(sensor_id);
	if (!p_dev)
		printk("sprd_mcu %s, error\n", __func__);
	else
		mutex_lock(&p_dev->sync_lock);
}

void sprd_sensor_sync_unlock(int sensor_id)
{
	struct sprd_sensor_dev_info_tag *p_dev;

	p_dev = sprd_sensor_get_dev_context(sensor_id);
	if (!p_dev)
		printk("sprd_mcu %s, error\n", __func__);
	else
		mutex_unlock(&p_dev->sync_lock);
}

static int sprd_sensor_regulator_enable(struct regulator *p_reg,
					struct sprd_sensor_dev_info_tag *p_dev,
					int type)
{
	int err = 0;

	err = regulator_enable(p_reg);

	if (err != 0)
		printk("sprd_mcu Error in regulator_enable: err %d", err);
	else
		p_dev->power_on_count[type]++;

	return err;
}

static int sprd_sensor_regulator_disable(struct regulator *p_reg,
					struct sprd_sensor_dev_info_tag *p_dev,
					int type)
{
	int err = 0;

	while (p_dev->power_on_count[type] > 0) {
		err = regulator_disable(p_reg);

		if (err != 0)
			printk("sprd_mcu Error in regulator_disable: err %d", err);
		else
			p_dev->power_on_count[type]--;
	}

	return err;
}

int sprd_sensor_set_voltage(int sensor_id, unsigned int val, int type)
{
	struct regulator *p_regulator = NULL;
	int ret = 0;
	struct sprd_sensor_dev_info_tag *p_dev = NULL;
	struct device *dev = NULL;

	p_dev = sprd_sensor_get_dev_context(sensor_id);
	if (p_dev == NULL) {
		printk("sped_mcu p_dev %d invalid sensor_id%d\n", type, sensor_id);
		return -EINVAL;
	}
	mutex_lock(&p_dev->set_voltage_lock);
	if (p_dev->regulator_supply[type] == NULL) {
		dev = &p_dev->i2c_info->dev;
		p_dev->regulator_supply[type] = devm_regulator_get(dev,
			sprd_sensor_supply_names[type]);
	}
	p_regulator = p_dev->regulator_supply[type];
	if (p_regulator == NULL) {
		printk("sped_mcu regulator %d invalid sensor_id%d\n", type, sensor_id);
		mutex_unlock(&p_dev->set_voltage_lock);
		return -EINVAL;
	}
	if (val) {
		ret = regulator_set_voltage(p_regulator, val, val);
		if (ret) {
			printk("sprd_mcu regulator %s vol set %d fail ret%d\n",
			       sprd_sensor_supply_names[type], val, ret);
			goto exit;
		}
		ret = sprd_sensor_regulator_enable(p_regulator, p_dev, type);
		if (ret) {
			devm_regulator_put(p_regulator);
			p_dev->regulator_supply[type] = NULL;
			printk("sprd_mcu regulator %s enable fail ret%d\n",
			       sprd_sensor_supply_names[type], ret);
			goto exit;
		}
	} else {
		if (p_regulator) {
			ret = sprd_sensor_regulator_disable(p_regulator,
				p_dev, type);
			if (ret) {
				printk("sprd_mcu regulator disable fail ret%d\n", ret);
			} else {
				devm_regulator_put(p_regulator);
				p_dev->regulator_supply[type] = NULL;
			}
		} else {
			printk("sprd_mcu regulator %s does not exist",
				sprd_sensor_supply_names[type]);
		}
	}

exit:
	mutex_unlock(&p_dev->set_voltage_lock);
	return ret;
}

int sprd_mcu_poweron_cammot(void)
{
	printk("sprd_mcu power on");
	sprd_sensor_sync_lock(SPRD_SENSOR_MAIN_ID_E);
	sprd_sensor_set_voltage(SPRD_SENSOR_MAIN_ID_E,
					SPRD_MCU_VDD_3300MV,
					SENSOR_REGULATOR_CAMMOT_ID_E);
	mdelay(1);
	sprd_sensor_sync_unlock(SPRD_SENSOR_MAIN_ID_E);
	return true;
}
EXPORT_SYMBOL(sprd_mcu_poweron_cammot);

int sprd_mcu_poweroff_cammot(void)
{
	printk("sprd_mcu power off");
	sprd_sensor_sync_lock(SPRD_SENSOR_MAIN_ID_E);
	sprd_sensor_set_voltage(SPRD_SENSOR_MAIN_ID_E,
				SPRD_MCU_VDD_CLOSED,
				SENSOR_REGULATOR_CAMMOT_ID_E);
	udelay(10);
	sprd_sensor_sync_unlock(SPRD_SENSOR_MAIN_ID_E);
	return true;
}
EXPORT_SYMBOL(sprd_mcu_poweroff_cammot);

static int sprd_sensor_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct device *dev = &client->dev;
	int i, ret = 0;
	struct sprd_sensor_dev_info_tag *pdata = NULL;

	pr_info("dcam sensor probe start:device name:%s\n", id->name);

	if (!dev->of_node) {
		printk("sprd_mcu no device node %s", __func__);
		return -ENODEV;
	}

	pdata = devm_kzalloc(dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;
	
	client->dev.platform_data = (void *)pdata;
	pdata->i2c_info = client;

	for (i = 0; i < SENSOR_REGULATOR_ID_MAX; i++)
		pdata->regulator_supply[i] = NULL;

	mutex_init(&pdata->sync_lock);
	mutex_init(&pdata->set_voltage_lock);
	atomic_set(&pdata->users, 0);

	pdata->sensor_id = SPRD_SENSOR_ID_MAX;
	if (of_device_is_compatible(dev->of_node, "sprd,sensor-main")) {
		pdata->sensor_id = SPRD_SENSOR_MAIN_ID_E;
		//ret = sprd_sensor_config(dev, pdata);
		s_sensor_dev_data[SPRD_SENSOR_MAIN_ID_E] = pdata;
	}

	sprd_mcu_poweron_cammot();

	return ret;
}

static int sprd_sensor_remove(struct i2c_client *client)
{
	struct sprd_sensor_dev_info_tag *pdata = NULL;
	int sensor_id = 0;

	pdata = (struct sprd_sensor_dev_info_tag *)client->dev.platform_data;
	if (pdata) {
		mutex_destroy(&pdata->sync_lock);
		mutex_destroy(&pdata->set_voltage_lock);
		sensor_id = pdata->sensor_id;
		devm_kfree(&client->dev, pdata);
	}

	pdata = NULL;
	client->dev.platform_data = NULL;
	s_sensor_dev_data[sensor_id] = NULL;

	return 0;
}

static const struct of_device_id sprd_sensor_main_of_match_table[] = {
	{.compatible = "sprd,sensor-main"},
};

static const struct i2c_device_id sprd_sensor_main_ids[] = {
	{}
};

static struct i2c_driver sprd_main_sensor_driver = {
	.driver = {
		.of_match_table =
		of_match_ptr(sprd_sensor_main_of_match_table),
		.name = SPRD_MCU_DRIVER_NAME,
		},
	.probe = sprd_sensor_probe,
	.remove = sprd_sensor_remove,
	.id_table = sprd_sensor_main_ids,
};

static int sprd_mcu_module_init(void)
{
	int ret = 0;

	memset(s_sensor_dev_data, 0, sizeof(s_sensor_dev_data));
	ret = i2c_add_driver(&sprd_main_sensor_driver);
	pr_info("register main sensor:%d\n", ret);

	return true;
}

static void sprd_mcu_module_exit(void)
{
	i2c_del_driver(&sprd_main_sensor_driver);
}

module_init(sprd_mcu_module_init);
module_exit(sprd_mcu_module_exit);

MODULE_DESCRIPTION("Spreadtrum Mcu Driver");
MODULE_LICENSE("GPL");