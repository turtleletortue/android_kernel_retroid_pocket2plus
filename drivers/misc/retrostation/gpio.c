#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/of_gpio.h>
#include <linux/of_device.h>
#include <linux/regulator/consumer.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

struct rs_gpio{
	int pin;
	char name[64];
};

static struct rs_gpio all_gpio_pin[]={
	{0,"boost_en"},
	{0,"fpga_io"},
	{0,"fpga_en"},
	{0,"speaker_en"},
	{0,"speaker_pa_power"},
};

void rs_gpio_set(const char* name, int value)
{
	int i;
	int size;

	size = sizeof(all_gpio_pin)/sizeof(struct rs_gpio);
	for(i = 0; i<size; i++){
		if(strcmp(name,all_gpio_pin[i].name) == 0){
			gpio_direction_output(all_gpio_pin[i].pin, value);
			printk("rs_gpio_set name:%s %d\n",name,value);
		}
	}
}
EXPORT_SYMBOL(rs_gpio_set);

int rs_gpio_get(const char* name)
{
	int i;
	int size;
	int value = -1;

	size = sizeof(all_gpio_pin)/sizeof(struct rs_gpio);
	for(i = 0; i<size; i++){
		if(strcmp(name,all_gpio_pin[i].name) == 0){
			value = gpio_get_value(all_gpio_pin[i].pin);
			break;
		}
	}
    printk("rs_gpio_get name:%s  %d\n",all_gpio_pin[i].name, value);
	return value;
}
EXPORT_SYMBOL(rs_gpio_get);

int rs_get_gpio_by_name(const char* name)
{
	int i;
	int size;
	int value = -1;

	size = sizeof(all_gpio_pin)/sizeof(struct rs_gpio);
	for(i = 0; i<size; i++){
		if(strcmp(name,all_gpio_pin[i].name) == 0){
			value = all_gpio_pin[i].pin;
			break;
		}
	}
    printk("rs_get_gpio_by_name name:%s  %d\n",all_gpio_pin[i].name, all_gpio_pin[i].pin);
	return value;
}
EXPORT_SYMBOL(rs_get_gpio_by_name);


static ssize_t sysfs_get_gpio(struct device *dev, struct device_attribute *attr, char * buf)
{
	int value;

	value = rs_gpio_get(attr->attr.name);
	printk("sysfs_get_gpio %s %d",attr->attr.name, value);
	return sprintf(buf, "%d\n", value);
}

static ssize_t sysfs_set_gpio(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
	int ret;
	unsigned int value = 0;
	
	ret = kstrtouint(buf, 0, &value);
	rs_gpio_set(attr->attr.name, value);
	printk("sysfs_set_gpio %s %d",attr->attr.name, value);
	return size;
}

static void rs_gpio_sysfs_init(struct kobject *kobj)
{
	int i;
	int size;
	struct device_attribute *dev;
	struct attribute **attr_array;
	struct attribute_group *group;

	size = sizeof(all_gpio_pin)/sizeof(struct rs_gpio);
	group = kzalloc(sizeof(struct attribute_group), GFP_KERNEL);
	attr_array = kzalloc(sizeof(struct attribute*)*(size+1), GFP_KERNEL);
	for(i = 0; i<size; i++){
		dev = kzalloc(sizeof(struct device_attribute), GFP_KERNEL);
		dev->show = sysfs_get_gpio;
		dev->store = sysfs_set_gpio;
		dev->attr.mode = 0644;
		dev->attr.name = all_gpio_pin[i].name;
		attr_array[i] = &dev->attr;
	}
	group->attrs = attr_array;
	if(sysfs_create_group(kobj, group) ) {
         printk("gpio sysfs_create_group failed\n");
    }
}

static int rs_gpio_probe(struct platform_device *pdev)
{
	int i;
	int size;
	struct device_node	*np;

	np = pdev->dev.of_node;
	size = sizeof(all_gpio_pin)/sizeof(struct rs_gpio);
	for(i = 0; i<size; i++){
		all_gpio_pin[i].pin = of_get_named_gpio(np, all_gpio_pin[i].name, 0);
		printk("rs_gpio_probe parse name:%s pin:%d\n",all_gpio_pin[i].name,all_gpio_pin[i].pin);
	}
	rs_gpio_sysfs_init(&pdev->dev.kobj);
	for(i = 0; i<size; i++){
		if(gpio_request(all_gpio_pin[i].pin, all_gpio_pin[i].name)<0)
			printk("rs_gpio_request %d error\n",all_gpio_pin[i].pin);
	}
	return 0;
}

static int rs_gpio_remove(struct platform_device *dev)
{	
	int i;
	int size;
	size = sizeof(all_gpio_pin)/sizeof(struct rs_gpio);
	for(i = 0; i<size; i++){
		gpio_free(all_gpio_pin[i].pin);
	}
	return 0;
}

static void rs_gpio_shutdown(struct platform_device *device)
{	

}

static struct of_device_id gpio_of_match[] = {
	{ .compatible = "retrostation,gpio", },
	{},
};

static struct platform_driver rs_gpio_driver = {
	.probe = rs_gpio_probe,
	.shutdown = rs_gpio_shutdown,
	.remove = rs_gpio_remove,
	.driver = {
			.name = "rs_gpio_driver",
			.of_match_table = gpio_of_match,
		   },
};

static int __init rs_gpio_init(void) 
{
	int ret = 0;	
	ret = platform_driver_register(&rs_gpio_driver);
	if (ret)
		printk("[gpio] platform_driver_register error:(%d)\n", ret);
	else
		printk("rs_gpio_init done!\n");
	return ret;
}

static void __exit rs_gpio_exit(void) 
{
	platform_driver_unregister(&rs_gpio_driver);
	printk("rs_gpio_exit Done!\n");
}

module_init(rs_gpio_init);
module_exit(rs_gpio_exit);

MODULE_LICENSE("GPL");
