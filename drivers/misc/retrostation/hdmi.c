#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/gpio.h>
#include <linux/pm.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/timer.h>
#include <linux/of_gpio.h>
#include <linux/of_address.h>
#include <linux/delay.h>
#include <linux/backlight.h>

struct hdmi_data {
	int hdmi_hpd_u3_irq;
	int hdmi_hpd_u3;
	int boost_en;
	int fpga_io;
	int fpga_en;
	int speaker_en;
	int speaker_pa_power;
	int brightness;
	int flag;
	int last_flag;
	
	struct kobject          *k_obj;
	struct platform_device  *pdev;
	struct device_node 	    *bl_node;
	struct backlight_device *backlight;
	struct work_struct hdmi_eint_work;	
	struct workqueue_struct *hdmi_eint_workqueue;
	wait_queue_head_t  wait_queue;
};

struct audio_state_machine_list_t
{
	char variate_name[64];
	int flag_offset;
	int current_status;
	int change_status;
	void (*execute_before)(void);
	void (*execute)(void);
	void (*execute_after)(void);
};

static struct file_operations hdmi_fops =
{
	.owner   = THIS_MODULE,
}; 

static struct miscdevice hdmi_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "retrostation_hdmi",
	.fops  = &hdmi_fops,
};

struct audio_state_machine_work_t
{
	const char *variate_name;
	int change_status;
	struct work_struct audio_state_machine_work;
};

extern int rs_gpio_get(const char* name);
extern int rs_get_gpio_by_name(const char* name);


static struct hdmi_data *hdmi_ctl;

/**audio three type variate **/
#define HDMI_EN 0
#define AUDIO_PLAY_EN 1
#define HEADSET_EN 2
#define SPEAKER_EN 3
#define SCREEN_EN 4

char *def_hdim_on[2] = {"default_hdmi_on", NULL};
char *def_hdim_off[2] = {"default_hdmi_off", NULL};


static int backlight_status = 0;
static int headset_type = 0;
static struct workqueue_struct *audio_state_machine_workqueue;
static int audio_status = 0;
static struct audio_state_machine_work_t *audio_work;

static int audio_state_get(int offset)
{
	return !!(audio_status & BIT(offset));
}

static void audio_state_set(int offset,int value)
{
	if(value)
		audio_status |= BIT(offset);
	else
		audio_status &= ~ BIT(offset);
}

static void lcd_backlight_enable(int status)
{	
	if(status){
		if(hdmi_ctl->brightness > 0){
			backlight_device_set_brightness(hdmi_ctl->backlight,hdmi_ctl->brightness);
			hdmi_ctl->brightness = 0;	
		}
	}else{
		if(hdmi_ctl->backlight->props.brightness > 0){
		hdmi_ctl->brightness = hdmi_ctl->backlight->props.brightness;
		backlight_device_set_brightness(hdmi_ctl->backlight,0);}
	}
}

static void hdmi_enable(int status)
{	
	if(status){
		gpio_set_value(hdmi_ctl->fpga_en,!!status);
		mdelay(200);
		gpio_set_value(hdmi_ctl->fpga_io,1);
		mdelay(10);
		gpio_set_value(hdmi_ctl->fpga_io,0);
		mdelay(10);
		gpio_set_value(hdmi_ctl->fpga_io,1);
	}else{
		gpio_set_value(hdmi_ctl->fpga_en,!!status);

	}
}

static void speaker_enable(int status)
{	
	if(status){
		gpio_set_value(hdmi_ctl->speaker_en,!status);
		mdelay(10);
		gpio_set_value(hdmi_ctl->speaker_pa_power,!!status);
		mdelay(10);
		gpio_set_value(hdmi_ctl->speaker_en,!!status);
	}else{
		gpio_set_value(hdmi_ctl->speaker_en,!!status);
		mdelay(10);
		gpio_set_value(hdmi_ctl->speaker_pa_power,!!status);
	}
}

static void hdmi_insert(void)
{
	if(!audio_state_get(SCREEN_EN))
		return;
	kobject_uevent_env(&hdmi_dev.this_device->kobj, KOBJ_CHANGE, def_hdim_on);
	hdmi_enable(1);
	speaker_enable(0);
	
	if(backlight_status == 0){
		lcd_backlight_enable(0);
	}
}

static void hdmi_pull_out(void)
{
	hdmi_enable(0);
	kobject_uevent_env(&hdmi_dev.this_device->kobj, KOBJ_CHANGE, def_hdim_off);
	if(audio_state_get(SPEAKER_EN) && !audio_state_get(HEADSET_EN))
	{
		speaker_enable(1);
	}

	if(backlight_status == 0){
		lcd_backlight_enable(1);
	}
}

static void audio_play_on(void)
{
	if(!audio_state_get(HEADSET_EN) && !(audio_state_get(HDMI_EN)))
		speaker_enable(1);
}

static void audio_play_on_before(void)
{
	mdelay(50);
}

static void audio_play_off(void)
{
	speaker_enable(0);
}

static void hdst_insert(void)
{
	speaker_enable(0);
}

static void hdst_pull_out(void)
{
	if(audio_state_get(SPEAKER_EN) && !audio_state_get(HDMI_EN)){
		mdelay(30);
		speaker_enable(1);}
}

static void set_headset_status(void)
{
  	char *envp[2];
	int type = (headset_type)?1:0;
  	int ret = audio_state_get(HEADSET_EN)? 1 : 0;
	if(ret){
		if(type == 1){
			envp[0] = "STATE=HEADPHONEPLUGED";
		}else{
			envp[0] = "STATE=HEADSETPLUGED";
			}	
	}else{
		envp[0] = "STATE=UNPLUGED";}
	envp[1] = NULL;
	ret = kobject_uevent_env(&hdmi_dev.this_device->kobj, KOBJ_CHANGE, envp);	//将evnp通过kobject上报
	printk("hdmi ret = %d",ret);
	return;
}

static void screen_on(void)
{
	if(audio_state_get(HDMI_EN))
	{
		kobject_uevent_env(&hdmi_dev.this_device->kobj, KOBJ_CHANGE, def_hdim_on);
		hdmi_enable(1);
		mdelay(2000);
		speaker_enable(0);
		if(backlight_status == 0){
			lcd_backlight_enable(0);
		}
	}
}

static void screen_off(void)
{
	if(audio_state_get(HDMI_EN))
	{
		hdmi_enable(0);
		kobject_uevent_env(&hdmi_dev.this_device->kobj, KOBJ_CHANGE, def_hdim_off);
		if(audio_state_get(SPEAKER_EN) && !audio_state_get(HEADSET_EN))
		{
			speaker_enable(1);
		}
	}
}

static struct audio_state_machine_list_t audio_state_machine_list[] = 
{
	{"HDMI",	 HDMI_EN,	0,1, NULL,				  hdmi_insert,   NULL},
	{"HDMI",	 HDMI_EN,	1,0, NULL,				  hdmi_pull_out, NULL},
	{"SPEAKER",	 SPEAKER_EN,0,1, audio_play_on_before,audio_play_on, NULL},
	{"SPEAKER",	 SPEAKER_EN,1,0, NULL,				  audio_play_off,NULL},
	{"HEADSET",	 HEADSET_EN,0,1, set_headset_status,  hdst_insert,   NULL},
	{"HEADSET",	 HEADSET_EN,1,0, set_headset_status,  hdst_pull_out, NULL},
	{"SCREEN_EN",SCREEN_EN,	0,1, NULL, 	  			  screen_on,  	 NULL},
	{"SCREEN_EN",SCREEN_EN,	1,0, NULL,    			  screen_off, 	 NULL},
};


static int get_audio_work_offset_by_name(const char * name)
{
	int i;
	for(i = 0; i < sizeof(audio_state_machine_list)/sizeof(struct audio_state_machine_list_t); ++i)
	{			
		if(strcmp(name, audio_state_machine_list[i].variate_name) == 0)
		{	
			return i;
		}		
	}
	return -1;
}

void audio_state_change(const char *name, int value)
{
	int i = 0;
	i = get_audio_work_offset_by_name(name);
	if(i < 0){
		printk("[audiodebug] match name error\n");
		return;
		}
	audio_work[i].variate_name = name;
	audio_work[i].change_status = value;
	queue_work(audio_state_machine_workqueue, &audio_work[i].audio_state_machine_work);
}
EXPORT_SYMBOL(audio_state_change);

void headset_type_set(int state)
{
	if(state < 0 || state > 4)
		return;
	headset_type = state;
}
EXPORT_SYMBOL(headset_type_set);

static void audio_state_machine_work_func(struct work_struct *work)
{	
	int i;
	int size;
	struct audio_state_machine_work_t *audio_state_data;
	audio_state_data = container_of(work, struct audio_state_machine_work_t, audio_state_machine_work);
	size = sizeof(audio_state_machine_list)/sizeof(struct audio_state_machine_list_t);
	printk("[audiodebug] start work %s\n",audio_state_data->variate_name);
	for(i = 0; i < size; ++i)
	{			
		if(strcmp(audio_state_data->variate_name, audio_state_machine_list[i].variate_name) == 0)
		{	
			if((audio_state_get(audio_state_machine_list[i].flag_offset) 
				== audio_state_machine_list[i].current_status) && 
				(audio_state_data->change_status == 
				audio_state_machine_list[i].change_status))
			{
				printk("[audiodebug]variate_name %s ,current_status is %d, change_status is %d\n",
					audio_state_data->variate_name,audio_state_machine_list[i].current_status,
					audio_state_data->change_status);
				audio_state_set(audio_state_machine_list[i].flag_offset,
					audio_state_machine_list[i].change_status);
				
				if(audio_state_machine_list[i].execute_before != NULL)
				audio_state_machine_list[i].execute_before();
				
				if(audio_state_machine_list[i].execute != NULL)
				audio_state_machine_list[i].execute();
				
				if(audio_state_machine_list[i].execute_after != NULL)
				audio_state_machine_list[i].execute_after();
			}
		}		
	}
}

static int get_backlight_device(void)
{
	struct device_node *bl_node;
	
	bl_node=of_find_compatible_node(NULL,NULL,"pwm-backlight");
	if(bl_node==NULL)
	{
		pr_err("get backlight node error!\n");
		return -1;
	}
	hdmi_ctl->backlight = of_find_backlight_by_node(bl_node);
	if(hdmi_ctl->backlight == NULL)
	{		
		return -1;
	}
	of_node_put(bl_node);
	return 0;
}

static int hdmi_parse_dt(struct platform_device *pdev)
{
	struct device_node *np;
	int ret;

	np = pdev->dev.of_node;
	
	hdmi_ctl->hdmi_hpd_u3 = of_get_named_gpio(np, "hdmi-hpd-u3-gpios", 0);
	if (!gpio_is_valid(hdmi_ctl->hdmi_hpd_u3))
		printk("can not get hdmi_hpd_u3 gpio\n");
	
	hdmi_ctl->hdmi_hpd_u3_irq = irq_of_parse_and_map(np,0);

	if(hdmi_ctl->hdmi_hpd_u3_irq < 0){
		printk("get hdmi_hpd_u3 irq error!\n");
		return ret;
	}

	return 0;
}

static ssize_t sysfs_get_lcdbl(struct device *dev, struct device_attribute *attr, char * buf)
{
	return sprintf(buf, "%d\n", backlight_status);
}

static ssize_t sysfs_set_lcdbl(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
	int ret;
	unsigned int value = 0;
	ret = kstrtouint(buf, 0, &value);
	if(hdmi_ctl->flag){
		lcd_backlight_enable(value);
		}
	backlight_status = value;
	return size;
}

static ssize_t sysfs_get_headset_state(struct device *dev, struct device_attribute *attr, char * buf)
{
	int type = (headset_type)?1:0;
	int ret = audio_state_get(HEADSET_EN)? 1 : 0;
	if(ret){
		if(type == 1){
			return sprintf(buf, "%s\n", "HEADPHONEPLUGED");
		}else{
			return sprintf(buf, "%s\n", "HEADSETPLUGED");
		}	
	}else{
		return sprintf(buf, "%s\n", "UNPLUGED");
	}	
}

static DEVICE_ATTR(lcdbl, 0644, sysfs_get_lcdbl, sysfs_set_lcdbl);
static DEVICE_ATTR(headset_state, 0644, sysfs_get_headset_state, NULL);

static struct attribute *sysfs_attributes[] = {
	&dev_attr_lcdbl.attr,
	&dev_attr_headset_state.attr,
    NULL
};

static struct attribute_group hdmi_attr_group = {
    .attrs = sysfs_attributes,
};

static void hdmi_sysfs_init(struct kobject *k_obj)
{
	if ((k_obj = kobject_create_and_add("hdmi", NULL)) == NULL ) {
         printk("[hdmi] sys node create error \n");
         return;
    }

	if(sysfs_create_group(k_obj, &hdmi_attr_group) ) {
         printk("[hdmi] sysfs_create_group failed\n");
    }
}

static void hdmi_eint_work_funs(struct work_struct *work)
{
	int level;
	
	mdelay(1000);
	level = gpio_get_value(hdmi_ctl->hdmi_hpd_u3);
	printk("irq hdmi_hpd_u3 is %d\n",level);

	if(level != hdmi_ctl->flag){
		hdmi_ctl->flag = level;
		if((hdmi_ctl->flag == 1) && (hdmi_ctl->last_flag == 0))
		{
			audio_state_change("HDMI",1);
		}
		else if((hdmi_ctl->flag == 0) && (hdmi_ctl->last_flag == 1))
		{
			audio_state_change("HDMI",0);
		}
		hdmi_ctl->last_flag = hdmi_ctl->flag;
	}

	enable_irq(hdmi_ctl->hdmi_hpd_u3_irq);
}

static irqreturn_t hdmi_eint_callback(int irq, void *data)
{	
	disable_irq_nosync(hdmi_ctl->hdmi_hpd_u3_irq);
	queue_work(hdmi_ctl->hdmi_eint_workqueue, &hdmi_ctl->hdmi_eint_work);

	return IRQ_HANDLED;
}

static int set_hdmi_u3_irq(void)
{
	int ret;

	ret = gpio_request(hdmi_ctl->hdmi_hpd_u3,"hdmi_hpd_u3");
	if(ret != 0){
		pr_err("hdmi_hpd_u3 gpio request failed(%d)\n",ret);
		return -1;
	}
	
	ret = gpio_direction_input(hdmi_ctl->hdmi_hpd_u3);
	if(ret != 0){
		pr_err("hdmi_hpd_u3 gpio set input failed\n");
	}

	ret = request_irq(hdmi_ctl->hdmi_hpd_u3_irq,hdmi_eint_callback,
			IRQ_TYPE_EDGE_BOTH ,"retroarch_hdmi", NULL);
	if(ret != 0){
		pr_err("[hdmi] EINT IRQ LINE NOT AVAILABLE\n");
		return -1;
	}

	ret = gpio_get_value(hdmi_ctl->hdmi_hpd_u3);
	
	enable_irq(hdmi_ctl->hdmi_hpd_u3_irq);
	return 0;
}

static int hdmi_gpio_init(void)
{	
	int ret;
    ret = set_hdmi_u3_irq();
	if(ret != 0){
		pr_err("Failed to set hdmi_u3_irq.\n");
		return ret;
	}

	hdmi_ctl->boost_en = rs_get_gpio_by_name("boost_en");
	if(hdmi_ctl->boost_en == -1)
	{
		pr_err("Failed to get boost_en gpio.\n");
	}
	hdmi_ctl->fpga_io = rs_get_gpio_by_name("fpga_io");
	if(hdmi_ctl->fpga_io == -1)
	{
		pr_err("Failed to get fpga_io gpio.\n");
	}
	hdmi_ctl->fpga_en = rs_get_gpio_by_name("fpga_en");
	if(hdmi_ctl->fpga_en == -1)
	{
		pr_err("Failed to get fpga_en gpio.\n");
	}
	hdmi_ctl->speaker_en = rs_get_gpio_by_name("speaker_en");
	if(hdmi_ctl->speaker_en == -1)
	{
		pr_err("Failed to get speaker_en gpio.\n");
	}
	hdmi_ctl->speaker_pa_power = rs_get_gpio_by_name("speaker_pa_power");
	if(hdmi_ctl->speaker_pa_power == -1)
	{
		pr_err("Failed to get speaker_pa_power gpio.\n");
	}
	
	gpio_direction_output(hdmi_ctl->boost_en,0);	
	gpio_direction_output(hdmi_ctl->fpga_en,0);	
	gpio_direction_output(hdmi_ctl->fpga_io,0);	
	gpio_direction_output(hdmi_ctl->speaker_en,0);	
	gpio_direction_output(hdmi_ctl->speaker_pa_power,0);	

	gpio_set_value(hdmi_ctl->boost_en,1);
	gpio_direction_output(hdmi_ctl->fpga_io,1);	
	
	return 0;
}

static int hdmi_probe(struct platform_device *pdev) 
{
	struct device *dev;
	int ret;
	int i;
	int work_num;
		
	dev = &pdev->dev;
	hdmi_ctl = devm_kzalloc(dev,sizeof(struct hdmi_data),GFP_KERNEL);
	if(!hdmi_ctl){
		return -EINVAL;
	}
	
	ret = hdmi_parse_dt(pdev);
	if (ret != 0) {
		pr_err("Failed to parse dt for hdmi_ctl_gpio.(%d)\n",ret);
		return ret;
	}

	/**create  thread workqueue.When the interrupt come，
	put the work to workqueue and then start the thread**/
	hdmi_ctl->hdmi_eint_workqueue = create_singlethread_workqueue("hdmi_eint");//创建工作队列
	INIT_WORK(&hdmi_ctl->hdmi_eint_work, hdmi_eint_work_funs);

	audio_state_machine_workqueue = create_singlethread_workqueue("speaker_control");
	if(audio_state_machine_workqueue == NULL)
	{	
		printk("create work error\n");
		destroy_workqueue(audio_state_machine_workqueue);
	}
	work_num = sizeof(audio_state_machine_list)/sizeof(struct audio_state_machine_list_t);
	audio_work = devm_kzalloc(dev,sizeof(struct audio_state_machine_work_t)*work_num,GFP_KERNEL);
	/**状态机状态初始化**/
	audio_state_set(SCREEN_EN,1);
	
	for(i = 0; i < work_num;++i)
	{
		INIT_WORK(&audio_work[i].audio_state_machine_work, audio_state_machine_work_func);
	}

	ret = hdmi_gpio_init();
	if(ret != 0){
		pr_err("Failed to init hdmi gpio.\n");
		return ret;
	}
	
	ret = get_backlight_device();
	if(ret != 0){
		pr_err("get backlight device error!\n");
	}

	hdmi_sysfs_init(hdmi_ctl->k_obj);

	misc_register(&hdmi_dev);
	
	return 0;
}

static int hdmi_remove(struct platform_device *dev)
{
	if (hdmi_ctl->hdmi_eint_workqueue){
		destroy_workqueue(hdmi_ctl->hdmi_eint_workqueue);
		}
	if(audio_state_machine_workqueue){
		destroy_workqueue(audio_state_machine_workqueue);
		}
	free_irq(hdmi_ctl->hdmi_hpd_u3_irq,NULL);	
	gpio_free(hdmi_ctl->hdmi_hpd_u3);
	return 0;
}

static const struct of_device_id hdmi_of_match[] = {
	{ .compatible = "eint-hdmi-hpd", },
	{},
};

static struct platform_driver hdmi_driver = {
	.driver   = {
		.name = "HDMI_Driver",
		.owner = THIS_MODULE,
		.of_match_table = hdmi_of_match,
	   },
	.probe    = hdmi_probe,
	.remove   = hdmi_remove,
};

static int __init hdmi_init(void) 
{
	int ret = 0;	
	ret = platform_driver_register(&hdmi_driver);
	if (ret)
		printk("[hdmi] platform_driver_register error:(%d)\n", ret);
	else
		printk("[hdmi] platform_driver_register done!\n");

	printk("[hdmi] hdmi_init done!\n");
	
	return ret;
}

static void __exit hdmi_exit(void) 
{
	platform_driver_unregister(&hdmi_driver);
}

late_initcall(hdmi_init);
module_exit(hdmi_exit);

MODULE_LICENSE("GPL");

