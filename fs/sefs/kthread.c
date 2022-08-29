/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 2008 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/mount.h>
#include "sefs_kernel.h"

struct sefs_open_req {
	struct file **lower_file;
	struct path path;
	struct completion done;
	struct list_head kthread_ctl_list;
};

static struct sefs_kthread_ctl {
#define SEFS_KTHREAD_ZOMBIE 0x00000001
	u32 flags;
	struct mutex mux;
	struct list_head req_list;
	wait_queue_head_t wait;
} sefs_kthread_ctl;

static struct task_struct *sefs_kthread;

/**
 * sefs_threadfn
 * @ignored: ignored
 *
 * The eCryptfs kernel thread that has the responsibility of getting
 * the lower file with RW permissions.
 *
 * Returns zero on success; non-zero otherwise
 */
static int sefs_threadfn(void *ignored)
{
	set_freezable();
	while (1)  {
		struct sefs_open_req *req;

		wait_event_freezable(
			sefs_kthread_ctl.wait,
			(!list_empty(&sefs_kthread_ctl.req_list)
			 || kthread_should_stop()));
		mutex_lock(&sefs_kthread_ctl.mux);
		if (sefs_kthread_ctl.flags & SEFS_KTHREAD_ZOMBIE) {
			mutex_unlock(&sefs_kthread_ctl.mux);
			goto out;
		}
		while (!list_empty(&sefs_kthread_ctl.req_list)) {
			req = list_first_entry(&sefs_kthread_ctl.req_list,
					       struct sefs_open_req,
					       kthread_ctl_list);
			list_del(&req->kthread_ctl_list);
			*req->lower_file = dentry_open(&req->path,
				(O_RDWR | O_LARGEFILE), current_cred());
			complete(&req->done);
		}
		mutex_unlock(&sefs_kthread_ctl.mux);
	}
out:
	return 0;
}

int __init sefs_init_kthread(void)
{
	int rc = 0;

	mutex_init(&sefs_kthread_ctl.mux);
	init_waitqueue_head(&sefs_kthread_ctl.wait);
	INIT_LIST_HEAD(&sefs_kthread_ctl.req_list);
	sefs_kthread = kthread_run(&sefs_threadfn, NULL,
				       "sefs-kthread");
	if (IS_ERR(sefs_kthread)) {
		rc = PTR_ERR(sefs_kthread);
		printk(KERN_ERR "%s: Failed to create kernel thread; rc = [%d]"
		       "\n", __func__, rc);
	}
	return rc;
}

void sefs_destroy_kthread(void)
{
	struct sefs_open_req *req, *tmp;

	mutex_lock(&sefs_kthread_ctl.mux);
	sefs_kthread_ctl.flags |= SEFS_KTHREAD_ZOMBIE;
	list_for_each_entry_safe(req, tmp, &sefs_kthread_ctl.req_list,
				 kthread_ctl_list) {
		list_del(&req->kthread_ctl_list);
		*req->lower_file = ERR_PTR(-EIO);
		complete(&req->done);
	}
	mutex_unlock(&sefs_kthread_ctl.mux);
	kthread_stop(sefs_kthread);
	wake_up(&sefs_kthread_ctl.wait);
}

/**
 * sefs_privileged_open
 * @lower_file: Result of dentry_open by root on lower dentry
 * @lower_dentry: Lower dentry for file to open
 * @lower_mnt: Lower vfsmount for file to open
 *
 * This function gets a r/w file opened against the lower dentry.
 *
 * Returns zero on success; non-zero otherwise
 */
int sefs_privileged_open(struct file **lower_file,
			     struct dentry *lower_dentry,
			     struct vfsmount *lower_mnt,
			     const struct cred *cred)
{
	struct sefs_open_req req;
	int flags = O_LARGEFILE;
	int rc = 0;

	init_completion(&req.done);
	req.lower_file = lower_file;
	req.path.dentry = lower_dentry;
	req.path.mnt = lower_mnt;

	/* Corresponding dput() and mntput() are done when the
	 * lower file is fput() when all eCryptfs files for the inode are
	 * released. */
	flags |= IS_RDONLY(d_inode(lower_dentry)) ? O_RDONLY : O_RDWR;
	(*lower_file) = dentry_open(&req.path, flags, cred);
	if (!IS_ERR(*lower_file))
		goto out;
	if ((flags & O_ACCMODE) == O_RDONLY) {
		rc = PTR_ERR((*lower_file));
		goto out;
	}
	mutex_lock(&sefs_kthread_ctl.mux);
	if (sefs_kthread_ctl.flags & SEFS_KTHREAD_ZOMBIE) {
		rc = -EIO;
		mutex_unlock(&sefs_kthread_ctl.mux);
		printk(KERN_ERR "%s: We are in the middle of shutting down; "
		       "aborting privileged request to open lower file\n",
			__func__);
		goto out;
	}
	list_add_tail(&req.kthread_ctl_list, &sefs_kthread_ctl.req_list);
	mutex_unlock(&sefs_kthread_ctl.mux);
	wake_up(&sefs_kthread_ctl.wait);
	wait_for_completion(&req.done);
	if (IS_ERR(*lower_file))
		rc = PTR_ERR(*lower_file);
out:
	return rc;
}
