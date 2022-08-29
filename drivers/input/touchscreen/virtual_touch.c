#include <linux/input.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/kernel.h>
#include <linux/input.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/input/mt.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/semaphore.h>
#include <uapi/linux/input.h>

#define VIRTUAL_TOUCH_NAME "rstouch"
#define is_touch_slot(e)        ((e)->code == ABS_MT_SLOT)
#define is_touch_id_up(e)       ((e)->code == ABS_MT_TRACKING_ID && (e)->value == 0xffffffff)
#define is_touch_down(e)        ((e)->code == BTN_TOUCH && (e)->value == 1)
#define is_touch_up(e)          ((e)->code == BTN_TOUCH && (e)->value == 0)
#define VIRTUAL_DOWN		0x01
#define VIRTUAL_UP			0x00

struct semaphore virtual_touch_sem;
static struct input_dev *input_dev_t;
extern int virtual_touch_empty(void);
extern int virtual_touch_create(void);
extern int relsease_identity(void *identity);
extern int slot_conver_mechanism(void *identity, int slot, int state, int source);

int virtual_touch_set_dev(struct input_dev *dev)
{
	input_dev_t = dev;
	return true;
}
EXPORT_SYMBOL(virtual_touch_set_dev);

static int rstouch_open(struct inode *inode, struct file *filp)
{
	if (!input_dev_t) {
		printk("virtual touch do not create touch input_dev\n");
		return -EINVAL;
	}
	return 0;
}

int create_virtual_touchscreen(void)
{
	int ret = 0;
	input_dev_t = input_allocate_device();
	if (input_dev_t == NULL) {
		printk("Failed to allocate input device.");
		return -ENOMEM;
	}

	input_dev_t->evbit[0] = BIT_MASK(EV_SYN) | BIT_MASK(EV_KEY) | BIT_MASK(EV_ABS);
	input_mt_init_slots(input_dev_t, 16, INPUT_MT_DIRECT);
	set_bit(INPUT_PROP_DIRECT, input_dev_t->propbit);

	input_set_abs_params(input_dev_t, ABS_MT_PRESSURE,    0, 255, 0, 0);
	input_set_abs_params(input_dev_t, ABS_MT_TOUCH_MAJOR, 0, 255, 0, 0);
	input_set_abs_params(input_dev_t, ABS_MT_WIDTH_MAJOR, 0, 200, 0, 0);
	input_set_abs_params(input_dev_t, ABS_MT_TRACKING_ID, 0,(5+1),0, 0);
	input_set_abs_params(input_dev_t, ABS_MT_POSITION_X, 0, 640,0, 0);
	input_set_abs_params(input_dev_t, ABS_MT_POSITION_Y, 0, 480,0, 0);

	input_dev_t->name = "virtual_ts";
	input_dev_t->phys = "input/ts";
	input_dev_t->id.bustype = BUS_I2C;

	ret = input_register_device(input_dev_t);
	if (ret) {
		printk("Register %s input device failed", input_dev_t->name);
		return -ENODEV;
	}
	return 0;
}
EXPORT_SYMBOL(create_virtual_touchscreen);

static int rstouch_release(struct inode *inode, struct file *filp)
{
	int slot = 0, count = 0;
	int ret;

	if (!input_dev_t) {
		printk("virtual touch do not create touch input_dev\n");
		return -EINVAL;
	}

	ret = down_interruptible(&virtual_touch_sem);
	do {
		slot = relsease_identity((void *)filp);
		if (slot != -1) {
			input_event(input_dev_t, EV_ABS, ABS_MT_SLOT, slot);
			input_event(input_dev_t, EV_ABS, ABS_MT_TRACKING_ID, -1);
			if (virtual_touch_empty()) {
				input_event(input_dev_t, EV_KEY, BTN_TOUCH, 0);
			}
			input_event(input_dev_t, EV_SYN, SYN_REPORT, 0);
		}
		count++;
	} while (slot != -1 && count <= 20);
	up(&virtual_touch_sem);
	return 0;
}

static int virtual_touch_unite(void *identity, struct input_event *buf, uint32_t count)
{
    int i, slot_original, slot_unite, not_send = -1;

    for (i = 0; i < count; i++) {
        if (is_touch_slot(buf + i)) {
            slot_original = buf[i].value;
            slot_unite = slot_conver_mechanism(identity, slot_original, VIRTUAL_DOWN, 1);
            buf[i].value = slot_unite;
        }
        if (is_touch_id_up(buf + i)) {
            slot_unite = slot_conver_mechanism(identity, slot_original, VIRTUAL_UP, 1);
        }
        if (is_touch_up(buf + i) && !virtual_touch_empty()) {
			not_send = i;
        }
    }

    return not_send;
}

static ssize_t rstouch_write(struct file *filp, const char *buff, size_t count, loff_t *offp)
{
	int ret, i, number, not_send;
	struct input_event *evnentbuf, *temp;

	if (!input_dev_t) {
		printk("virtual touch do not create touch input_dev\n");
		return -EINVAL;
	}

	evnentbuf = (struct input_event *) kmalloc(sizeof(char) * count, GFP_KERNEL);
	temp = evnentbuf;
	number = count / sizeof(struct input_event);

	/* Parameter validity check */
	if (!access_ok(VERIFY_WRITE, buff, count))
		return -EFAULT;
	ret = copy_from_user((void *)evnentbuf, buff, count);
	if (ret != 0) {
		printk("%s number %d rstouch_write kernel write failed!\r\n", __FUNCTION__, ret);
		return -EFAULT;
	}

	ret = down_interruptible(&virtual_touch_sem);
	not_send = virtual_touch_unite((void *)filp, evnentbuf, number);

	for (i = 0; i < number; i++) {
		if (not_send != i)
			input_event(input_dev_t, temp->type, temp->code, temp->value);
		temp++;
	}
	up(&virtual_touch_sem);

	kfree(evnentbuf);
	return count;
}

static struct file_operations rstouch_fops = {
	.owner = THIS_MODULE,
	.open = rstouch_open,
	.write = rstouch_write,
	.release = rstouch_release,
};

static struct miscdevice rstouch_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = VIRTUAL_TOUCH_NAME,
	.fops = &rstouch_fops,
};

static int rstouch_probe(struct platform_device *pdev)
{
    int ret = misc_register(&rstouch_miscdev);
	if(ret < 0){
		printk("misc device register failed!\r\n");
		return -EFAULT;
	}
	sema_init(&virtual_touch_sem, 1);

	return 0;
}

static int rstouch_remove(struct platform_device *pdev)
{
	misc_deregister(&rstouch_miscdev);
	return 0;
}

struct platform_driver rstouch_driver = {
    .driver.name = "virtual_touch",
    .probe = rstouch_probe,
    .remove = rstouch_remove,
};

static int __init rstouch_init(void)
{
	platform_driver_register(&rstouch_driver);
	virtual_touch_create();
	rstouch_probe(NULL);

	return 0;
}

static void __exit rstouch_exit(void)
{
	rstouch_remove(NULL);
    platform_driver_unregister(&rstouch_driver);

	return ;
}

module_platform_driver(rstouch_driver);

module_init(rstouch_init);
module_exit(rstouch_exit);