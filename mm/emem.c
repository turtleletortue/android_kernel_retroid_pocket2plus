/* mm/emem.c
 *
 * The enhance meminfo show system memory information, when processes with
 * r ange of oom_score_adj values will get killed. The killed process
 * oom_score_adj values is written in /proc/sys/vm/emem_trigger. If the
 * written value is less then Threshold, the meminfo is shown.
 * Threshold of killed process adj is set in
 * /sys/module/emem/parameters/killed_proc_adj_threshold
 *
 * Copyright (C) 2018-2019 UNISOC, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/oom.h>
#include <linux/rcupdate.h>
#include <linux/profile.h>
#include <linux/notifier.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/workqueue.h>

#define  DEFAULT_PROC_ADJ    900

/*
 * The written value is the killed process adj, then trigger to show enhance
 * memory information. it's written to /proc/sys/vm/emem_trigger
 */
int sysctl_emem_trigger;

static struct work_struct emem_work;
static DEFINE_SPINLOCK(emem_lock);
/* User knob to enable/disable enhance meminfo feature */
static int enable_enhance_meminfo;
/* killed process oom score adj threshold */
static int killed_proc_adj_threshold = 200;

module_param_named(enable, enable_enhance_meminfo, int, 0644);
module_param_named(killed_proc_adj_threshold, killed_proc_adj_threshold,
		int, 0644);

static void dump_tasks_info(void)
{
	struct task_struct *p;
	struct task_struct *task;

	pr_info("[ pid ]   uid  tgid total_vm      rss   swap cpu oom_score_adj name\n");
	rcu_read_lock();
	for_each_process(p) {
		/* check unkillable tasks */
		if (is_global_init(p))
			continue;
		if (p->flags & PF_KTHREAD)
			continue;

		task = find_lock_task_mm(p);
		if (!task) {
			/*
			 * This is a kthread or all of p's threads have already
			 * detached their mm's.  There's no need to report
			 * them; they can't be oom killed anyway.
			 */
			continue;
		}

		pr_info("[%5d] %5d %5d %8lu %8lu %6lu %3u         %5d %s\n",
			task->pid, from_kuid(&init_user_ns, task_uid(task)),
			task->tgid, task->mm->total_vm, get_mm_rss(task->mm),
			get_mm_counter(task->mm, MM_SWAPENTS),
			task_cpu(task),
			task->signal->oom_score_adj, task->comm);
		task_unlock(task);
	}
	rcu_read_unlock();
}

static void enhance_meminfo(void)
{
	struct timeval val;
	static u64 last_time = 0;

	do_gettimeofday(&val);
	if (val.tv_sec - last_time > 1) {
		pr_info("+++++++++++++++++++++++++++++++++++++++++++++++++\n");
		pr_info("The killed process adj = %d\n", sysctl_emem_trigger);
		enhanced_show_mem(E_SHOW_MEM_ALL);
		last_time = val.tv_sec;
	}
}

static void emem_workfn(struct work_struct *work)
{
	if (sysctl_emem_trigger > killed_proc_adj_threshold)
		return;

	if (enable_enhance_meminfo)
		enhance_meminfo();
}

int sysctl_emem_trigger_handler(struct ctl_table *table, int write,
			void __user *buffer, size_t *length, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (ret || !write)
		return -1;

	if (sysctl_emem_trigger < DEFAULT_PROC_ADJ) {
		spin_lock(&emem_lock);
		queue_work(system_power_efficient_wq, &emem_work);
		spin_unlock(&emem_lock);
	}
	return 0;
}

static int tasks_e_show_mem_handler(struct notifier_block *nb,
			unsigned long val, void *data)
{
	enum e_show_mem_type type = val;
	struct sysinfo si;

	si_swapinfo(&si);
	pr_info("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	pr_info("Enhanced Mem-info :TASK\n");
	pr_info("Detail:\n");
	if (E_SHOW_MEM_CLASSIC == type || E_SHOW_MEM_ALL == type)
		dump_tasks_info();
	pr_info("Total used:\n");
	pr_info("     anon: %lu kB\n", ((global_node_page_state(NR_ACTIVE_ANON)
		     + global_node_page_state(NR_INACTIVE_ANON)) << PAGE_SHIFT)
			/ 1024);
	pr_info("   swaped: %lu kB\n", ((si.totalswap - si.freeswap)
		<< PAGE_SHIFT) / 1024);

	return 0;
}

static struct notifier_block tasks_e_show_mem_notifier = {
	.notifier_call = tasks_e_show_mem_handler,
};

static int __init emem_init(void)
{
	INIT_WORK(&emem_work, emem_workfn);
	register_e_show_mem_notifier(&tasks_e_show_mem_notifier);
	return 0;
}

subsys_initcall(emem_init);

