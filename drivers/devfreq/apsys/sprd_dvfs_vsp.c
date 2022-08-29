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

#include "sprd_dvfs_vsp.h"

LIST_HEAD(vsp_dvfs_head);

struct sprd_vsp_dvfs_data {
	const char *ver;
	u32 max_freq_level;
};

static const struct sprd_vsp_dvfs_data sharkl5_vsp_data = {
	.ver = "sharkl5",
	.max_freq_level = 3,
};

static const struct of_device_id vsp_dvfs_of_match[] = {
	{ .compatible = "sprd,hwdvfs-vsp-sharkl5",
	  .data = &sharkl5_vsp_data },
	{ },
};

MODULE_DEVICE_TABLE(of, vsp_dvfs_of_match);

BLOCKING_NOTIFIER_HEAD(vsp_dvfs_chain);

int vsp_dvfs_notifier_call_chain(void *data)
{
	return blocking_notifier_call_chain(&vsp_dvfs_chain, 0, data);
}
EXPORT_SYMBOL_GPL(vsp_dvfs_notifier_call_chain);

static ssize_t get_dvfs_enable_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct devfreq *devfreq = to_devfreq(dev);
	struct vsp_dvfs *vsp = dev_get_drvdata(devfreq->dev.parent);
	int ret = 0;

	ret = sprintf(buf, "%d\n", vsp->ip_coeff.hw_dfs_en);

	return ret;
}

static ssize_t set_dvfs_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct devfreq *devfreq = to_devfreq(dev);
	struct vsp_dvfs *vsp = dev_get_drvdata(devfreq->dev.parent);
	u32 user_en;
	int ret;

	ret = sscanf(buf, "%u\n", &user_en);
	if (ret != 1)
		return -EINVAL;

	if (vsp->dvfs_ops && vsp->dvfs_ops->hw_dvfs_en) {
		vsp->dvfs_ops->hw_dvfs_en(user_en);
		vsp->ip_coeff.hw_dfs_en = user_en;
	}
	else
		pr_info("%s: ip ops null\n", __func__);
	ret = count;

	return ret;
}

static ssize_t get_work_freq_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct devfreq *devfreq = to_devfreq(dev);
	struct vsp_dvfs *vsp = dev_get_drvdata(devfreq->dev.parent);
	u32 work_freq;
	int ret = 0;

	if (vsp->dvfs_ops && vsp->dvfs_ops->get_work_freq) {
		work_freq = vsp->dvfs_ops->get_work_freq();
		ret = sprintf(buf, "%u\n", work_freq);
	}
	else
		ret = sprintf(buf, "undefined\n");

	return ret;
}

static ssize_t set_work_freq_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct devfreq *devfreq = to_devfreq(dev);
	struct vsp_dvfs *vsp = dev_get_drvdata(devfreq->dev.parent);
	u32 user_freq;
	int ret;

	mutex_lock(&devfreq->lock);
	ret = sscanf(buf, "%u\n", &user_freq);
	if (ret != 1) {
		mutex_unlock(&devfreq->lock);
		return -EINVAL;
	}
	pr_info("%s: dvfs freq %u", __func__, user_freq);
	vsp->work_freq = user_freq;
	vsp->freq_type = DVFS_WORK;

	ret = update_devfreq(devfreq);
	if (ret == 0)
		ret = count;

	mutex_unlock(&devfreq->lock);

	return ret;
}

static ssize_t get_idle_freq_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct devfreq *devfreq = to_devfreq(dev);
	struct vsp_dvfs *vsp = dev_get_drvdata(devfreq->dev.parent);
	int ret = 0;
	u32 idle_freq;

	if (vsp->dvfs_ops && vsp->dvfs_ops->get_idle_freq) {
		idle_freq = vsp->dvfs_ops->get_idle_freq();
		ret = sprintf(buf, "%d\n", idle_freq);
	}
	else
		ret = sprintf(buf, "undefined\n");

	return ret;

}

static ssize_t set_idle_freq_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct devfreq *devfreq = to_devfreq(dev);
	struct vsp_dvfs *vsp = dev_get_drvdata(devfreq->dev.parent);
	u32 idle_freq;
	int ret;

	mutex_lock(&devfreq->lock);
	ret = sscanf(buf, "%u\n", &idle_freq);
	if (ret != 1) {
		mutex_unlock(&devfreq->lock);
		return -EINVAL;
	}
	vsp->idle_freq = idle_freq;
	vsp->freq_type = DVFS_IDLE;
	ret = update_devfreq(devfreq);
	if (ret == 0)
		ret = count;
	mutex_unlock(&devfreq->lock);

	return ret;

}

static ssize_t get_work_index_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct devfreq *devfreq = to_devfreq(dev);
	struct vsp_dvfs *vsp = dev_get_drvdata(devfreq->dev.parent);
	int ret = 0, work_index;

	if (vsp->dvfs_ops && vsp->dvfs_ops->get_work_index) {
		work_index = vsp->dvfs_ops->get_work_index();
		ret = sprintf(buf, "%d\n", work_index);
	}
	else
		ret = sprintf(buf, "undefined\n");

	return ret;
}

static ssize_t set_work_index_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct devfreq *devfreq = to_devfreq(dev);
	struct vsp_dvfs *vsp = dev_get_drvdata(devfreq->dev.parent);
	u32 work_index;
	int ret;

	ret = sscanf(buf, "%u\n", &work_index);
	if (ret != 1)
		return -EINVAL;

	if (vsp->dvfs_ops && vsp->dvfs_ops->set_work_index)
		vsp->dvfs_ops->set_work_index(work_index);
	else
		pr_info("%s: ip ops null\n", __func__);

	return count;
}

static ssize_t get_idle_index_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct devfreq *devfreq = to_devfreq(dev);
	struct vsp_dvfs *vsp = dev_get_drvdata(devfreq->dev.parent);
	int ret = 0, idle_index;

	if (vsp->dvfs_ops && vsp->dvfs_ops->get_idle_index) {
		idle_index = vsp->dvfs_ops->get_idle_index();
		ret = sprintf(buf, "%d\n", idle_index);
	}
	else
		ret = sprintf(buf, "undefined\n");

	return ret;
}

static ssize_t set_idle_index_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct devfreq *devfreq = to_devfreq(dev);
	struct vsp_dvfs *vsp = dev_get_drvdata(devfreq->dev.parent);
	u32 idle_index;
	int ret;

	ret = sscanf(buf, "%u\n", &idle_index);
	if (ret != 1)
		return -EINVAL;

	if (vsp->dvfs_ops && vsp->dvfs_ops->set_idle_index)
		vsp->dvfs_ops->set_idle_index(idle_index);
	else
		pr_info("%s: ip ops null\n", __func__);

	return count;
}

static ssize_t get_dvfs_status_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct devfreq *devfreq = to_devfreq(dev);
	struct vsp_dvfs *vsp = dev_get_drvdata(devfreq->dev.parent);
	struct ip_dvfs_status ip_status;
	ssize_t len = 0;

	if (vsp->dvfs_ops && vsp->dvfs_ops->get_dvfs_status)
		vsp->dvfs_ops->get_dvfs_status(&ip_status);
	else {
		len = sprintf(buf, "undefined\n");
		return len;
	}

	len = sprintf(buf, "apsys_cur_volt\tvsp_vote_volt\t"
			"dpu_vote_volt\tvdsp_vote_volt\n");

	len += sprintf(buf + len, "%s\t\t%s\t\t%s\t\t%s\n",
			ip_status.apsys_cur_volt, ip_status.vsp_vote_volt,
			ip_status.dpu_vote_volt, ip_status.vdsp_vote_volt);

	len += sprintf(buf + len, "\t\tvsp_cur_freq\tdpu_cur_freq\t"
			"vdsp_cur_freq\n");

	len += sprintf(buf + len, "\t\t%s\t\t%s\t\t%s\n",
			ip_status.vsp_cur_freq, ip_status.dpu_cur_freq,
			ip_status.vdsp_cur_freq);

	return len;
}


static ssize_t get_dvfs_table_info_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct devfreq *devfreq = to_devfreq(dev);
	struct vsp_dvfs *vsp = dev_get_drvdata(devfreq->dev.parent);
	struct ip_dvfs_map_cfg dvfs_table[MAX_FREQ_LEVEL];
	ssize_t len = 0;
	int i;

	if (vsp->dvfs_ops && vsp->dvfs_ops->get_dvfs_table)
		vsp->dvfs_ops->get_dvfs_table(dvfs_table);
	else {
		pr_info("%s: ip ops null\n", __func__);
		return len;
	}

	len = sprintf(buf, "map_index\tvolt_level\tclk_level\tclk_rate\n");
	for (i = 0; i < vsp->max_freq_level; i++) {
		len += sprintf(buf+len, "%d\t\t%d (%s)\t%d\t\t%d\t\t\n",
				dvfs_table[i].map_index,
				dvfs_table[i].volt_level,
				dvfs_table[i].volt_val,
				dvfs_table[i].clk_level,
				dvfs_table[i].clk_rate);
	}

	return len;
}

/*sys for gov_entries*/
static DEVICE_ATTR(dvfs_enable, 0644, get_dvfs_enable_show,
				   set_dvfs_enable_store);
static DEVICE_ATTR(work_freq, 0644, get_work_freq_show,
				   set_work_freq_store);
static DEVICE_ATTR(idle_freq, 0644, get_idle_freq_show,
				   set_idle_freq_store);
static DEVICE_ATTR(work_index, 0644, get_work_index_show,
				   set_work_index_store);
static DEVICE_ATTR(idle_index, 0644, get_idle_index_show,
				   set_idle_index_store);
static DEVICE_ATTR(dvfs_status, 0644, get_dvfs_status_show, NULL);
static DEVICE_ATTR(dvfs_table, 0644, get_dvfs_table_info_show, NULL);

static struct attribute *dev_entries[] = {
	&dev_attr_dvfs_enable.attr,
	&dev_attr_work_freq.attr,
	&dev_attr_idle_freq.attr,
	&dev_attr_work_index.attr,
	&dev_attr_idle_index.attr,
	&dev_attr_dvfs_status.attr,
	&dev_attr_dvfs_table.attr,
	NULL,
};

static struct attribute_group dev_attr_group = {
	.name    = "vsp_governor",
	.attrs    = dev_entries,
};

static void userspace_exit(struct devfreq *devfreq)
{
	/*
	 * Remove the sysfs entry, unless this is being called after
	 * device_del(), which should have done this already via kobject_del().
	 */
	if (devfreq->dev.kobj.sd)
		sysfs_remove_group(&devfreq->dev.kobj, &dev_attr_group);
}

static int userspace_init(struct devfreq *devfreq)
{
	int ret = 0;

	ret = sysfs_create_group(&devfreq->dev.kobj, &dev_attr_group);

	return ret;
}

static int vsp_dvfs_gov_get_target(struct devfreq *devfreq,
		unsigned long *freq)
{
	struct vsp_dvfs *vsp = dev_get_drvdata(devfreq->dev.parent);
	unsigned long adjusted_freq = 0;

	pr_debug("devfreq_governor-->get_target_freq\n");

	if (vsp->freq_type == DVFS_WORK)
		adjusted_freq = vsp->work_freq;
	else
		adjusted_freq = vsp->idle_freq;

	if (devfreq->max_freq && adjusted_freq > devfreq->max_freq)
		adjusted_freq = devfreq->max_freq;

	if (devfreq->min_freq && adjusted_freq < devfreq->min_freq)
		adjusted_freq = devfreq->min_freq;

	*freq = adjusted_freq;

	pr_debug("dvfs *freq %lu", *freq);
	return 0;
}

static int vsp_dvfs_gov_event_handler(struct devfreq *devfreq,
		unsigned int event, void *data)
{
	int ret = 0;

	pr_info("devfreq_governor-->event_handler(%d)\n", event);
	switch (event) {
	case DEVFREQ_GOV_START:
		ret = userspace_init(devfreq);
		break;
	case DEVFREQ_GOV_STOP:
		userspace_exit(devfreq);
		break;
	default:
		break;
	}

	return ret;
}

struct devfreq_governor vsp_dvfs_gov = {
	.name = "vsp_dvfs",
	.get_target_freq = vsp_dvfs_gov_get_target,
	.event_handler = vsp_dvfs_gov_event_handler,
};

static int vsp_dvfs_notify_callback(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct vsp_dvfs *vsp = container_of(nb, struct vsp_dvfs, vsp_dvfs_nb);
	u32 dvfs_freq = *(int *)data;

	mutex_lock(&vsp->devfreq->lock);

	if (!vsp->ip_coeff.hw_dfs_en) {
		pr_info("vsp dvfs is disabled, nothing to do");
		mutex_unlock(&vsp->devfreq->lock);
		return NOTIFY_DONE;
	}

	vsp->work_freq = dvfs_freq;
	vsp->freq_type = DVFS_WORK;
	update_devfreq(vsp->devfreq);
	mutex_unlock(&vsp->devfreq->lock);

	return NOTIFY_OK;
}

static int vsp_dvfs_target(struct device *dev, unsigned long *freq,
		u32 flags)
{
	struct vsp_dvfs *vsp = dev_get_drvdata(dev);
	struct dev_pm_opp *opp;
	unsigned long target_freq;
	int ret = 0;

	pr_debug("devfreq_dev_profile-->target, freq=%lu\n", *freq);
	opp = devfreq_recommended_opp(dev, freq, flags);

	if (IS_ERR(opp)) {
		dev_err(dev, "Failed to find opp for %lu KHz\n", *freq);
		return PTR_ERR(opp);
	}

	target_freq = dev_pm_opp_get_freq(opp);
	pr_debug("target freq from opp %lu\n", target_freq);
	dev_pm_opp_put(opp);

	if (vsp->freq_type == DVFS_WORK)
		vsp->work_freq = target_freq;
	else
		vsp->idle_freq = target_freq;
	vsp->dvfs_ops->updata_target_freq(target_freq, vsp->freq_type);

	if (ret) {
		dev_err(dev, "Cannot to set freq:%lu to vsp, ret: %d\n",
		target_freq, ret);
	}

	return ret;
}

int vsp_dvfs_get_dev_status(struct device *dev,
		struct devfreq_dev_status *stat)
{
	struct vsp_dvfs *vsp = dev_get_drvdata(dev);
	struct devfreq_event_data edata;
	int ret = 0;

	pr_info("devfreq_dev_profile-->get_dev_status\n");
	ret = devfreq_event_get_event(vsp->edev, &edata);

	if (ret < 0)
		return ret;

	stat->current_frequency = vsp->freq;
	stat->busy_time = edata.load_count;
	stat->total_time = edata.total_count;

	return ret;
}

static int vsp_dvfs_get_cur_freq(struct device *dev, unsigned long *freq)
{
	struct vsp_dvfs *vsp = dev_get_drvdata(dev);

	if (vsp->freq_type == DVFS_WORK)
		*freq = vsp->work_freq;
	else
		*freq = vsp->idle_freq;
	pr_debug("devfreq_dev_profile-->get_cur_freq, *freq=%lu\n", *freq);

	return 0;
}
static struct devfreq_dev_profile vsp_dvfs_profile = {
	.target             = vsp_dvfs_target,
	.get_dev_status     = vsp_dvfs_get_dev_status,
	.get_cur_freq       = vsp_dvfs_get_cur_freq,
};

static int vsp_dvfs_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = pdev->dev.of_node;
	struct vsp_dvfs *vsp;
	int ret;
	struct sprd_vsp_dvfs_data *data = NULL;

	vsp = devm_kzalloc(dev, sizeof(*vsp), GFP_KERNEL);
	if (!vsp)
		return -ENOMEM;

	data = (struct sprd_vsp_dvfs_data *)of_device_get_match_data(dev);
	vsp->max_freq_level = data->max_freq_level;
	vsp->dvfs_ops = vsp_dvfs_ops_attach(data->ver);
	pr_info("attach dvfs ops %s\n", data->ver);

	if (!vsp->dvfs_ops) {
		pr_err("attach dvfs ops %s failed\n", data->ver);
		return -EINVAL;
	}

	of_property_read_u32(np, "sprd,dvfs-work-freq",
			&vsp->work_freq);
	of_property_read_u32(np, "sprd,dvfs-idle-freq",
			&vsp->idle_freq);
	of_property_read_u32(np, "sprd,dvfs-enable-flag",
			&vsp->ip_coeff.hw_dfs_en);
	pr_info("work freq %d, idle freq %d, enable flag %d\n",
			vsp->work_freq,
			vsp->idle_freq,
			vsp->ip_coeff.hw_dfs_en);

	if (dev_pm_opp_of_add_table(dev)) {
		dev_err(dev, "Invalid operating-points in device tree.\n");
		return -EINVAL;
	}
	vsp->vsp_dvfs_nb.notifier_call = vsp_dvfs_notify_callback;
	ret = blocking_notifier_chain_register(&vsp_dvfs_chain,
			&vsp->vsp_dvfs_nb);

	platform_set_drvdata(pdev, vsp);
	vsp->devfreq = devm_devfreq_add_device(dev,
					&vsp_dvfs_profile,
					"vsp_dvfs",
					NULL);
	if (IS_ERR(vsp->devfreq)) {
		dev_err(dev,
		"failed to add devfreq dev with vsp-dvfs governor\n");
		ret = PTR_ERR(vsp->devfreq);
		goto ret;
	}
	device_rename(&vsp->devfreq->dev, "vsp");

	if (vsp->dvfs_ops && vsp->dvfs_ops->parse_dt)
		vsp->dvfs_ops->parse_dt(vsp, np);
	if (vsp->dvfs_ops && vsp->dvfs_ops->dvfs_init)
		vsp->dvfs_ops->dvfs_init(vsp);

	pr_info("Succeeded to register a vsp dvfs device\n");

	return 0;

ret:
	dev_pm_opp_of_remove_table(dev);
	blocking_notifier_chain_unregister(&vsp_dvfs_chain, &vsp->vsp_dvfs_nb);

	return ret;
}

static int vsp_dvfs_remove(struct platform_device *pdev)
{
	return 0;
}

static __maybe_unused int vsp_dvfs_suspend(struct device *dev)
{
	pr_info("%s()\n", __func__);

	return 0;
}

static __maybe_unused int vsp_dvfs_resume(struct device *dev)
{
	struct vsp_dvfs *vsp = dev_get_drvdata(dev);

	pr_info("%s()\n", __func__);

	if (vsp->dvfs_ops && vsp->dvfs_ops->dvfs_init)
		vsp->dvfs_ops->dvfs_init(vsp);

	return 0;
}

static SIMPLE_DEV_PM_OPS(vsp_dvfs_pm, vsp_dvfs_suspend,
			 vsp_dvfs_resume);

static struct platform_driver vsp_dvfs_driver = {
	.probe    = vsp_dvfs_probe,
	.remove     = vsp_dvfs_remove,
	.driver = {
		.name = "vsp-dvfs",
		.pm = &vsp_dvfs_pm,
		.of_match_table = vsp_dvfs_of_match,
	},
};

int __init vsp_dvfs_init(void)
{
	int ret = 0;

	if (ret) {
		pr_err("%s: failed to add ops: %d\n", __func__, ret);
		return ret;
	}

	ret = devfreq_add_governor(&vsp_dvfs_gov);
	if (ret) {
		pr_err("%s: failed to add governor: %d\n", __func__, ret);
		return ret;
	}

	ret = platform_driver_register(&vsp_dvfs_driver);

	if (ret)
		devfreq_remove_governor(&vsp_dvfs_gov);

	return ret;
}

void __exit vsp_dvfs_exit(void)
{
	int ret = 0;

	platform_driver_unregister(&vsp_dvfs_driver);

	ret = devfreq_remove_governor(&vsp_dvfs_gov);
	if (ret)
		pr_err("%s: failed to remove governor: %d\n", __func__, ret);

	if (ret)
		pr_err("%s: failed to remove ops: %d\n", __func__, ret);
}

module_init(vsp_dvfs_init);
module_exit(vsp_dvfs_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Sprd vsp devfreq driver");
MODULE_AUTHOR("Chunlei Guo <chunlei.guo@unisoc.com>");

