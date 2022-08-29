/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 2004-2008 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
 *		Tyler Hicks <tyhicks@ou.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
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
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/nsproxy.h>
#include "sefs_kernel.h"

static LIST_HEAD(sefs_msg_ctx_free_list);
static LIST_HEAD(sefs_msg_ctx_alloc_list);
static struct mutex sefs_msg_ctx_lists_mux;

static struct hlist_head *sefs_daemon_hash;
struct mutex sefs_daemon_hash_mux;
static int sefs_hash_bits;
#define sefs_current_euid_hash(uid) \
	hash_long((unsigned long)from_kuid(&init_user_ns, current_euid()), sefs_hash_bits)

static u32 sefs_msg_counter;
static struct sefs_msg_ctx *sefs_msg_ctx_arr;

/**
 * sefs_acquire_free_msg_ctx
 * @msg_ctx: The context that was acquired from the free list
 *
 * Acquires a context element from the free list and locks the mutex
 * on the context.  Sets the msg_ctx task to current.  Returns zero on
 * success; non-zero on error or upon failure to acquire a free
 * context element.  Must be called with sefs_msg_ctx_lists_mux
 * held.
 */
static int sefs_acquire_free_msg_ctx(struct sefs_msg_ctx **msg_ctx)
{
	struct list_head *p;
	int rc;

	if (list_empty(&sefs_msg_ctx_free_list)) {
		printk(KERN_WARNING "%s: The eCryptfs free "
		       "context list is empty.  It may be helpful to "
		       "specify the sefs_message_buf_len "
		       "parameter to be greater than the current "
		       "value of [%d]\n", __func__, sefs_message_buf_len);
		rc = -ENOMEM;
		goto out;
	}
	list_for_each(p, &sefs_msg_ctx_free_list) {
		*msg_ctx = list_entry(p, struct sefs_msg_ctx, node);
		if (mutex_trylock(&(*msg_ctx)->mux)) {
			(*msg_ctx)->task = current;
			rc = 0;
			goto out;
		}
	}
	rc = -ENOMEM;
out:
	return rc;
}

/**
 * sefs_msg_ctx_free_to_alloc
 * @msg_ctx: The context to move from the free list to the alloc list
 *
 * Must be called with sefs_msg_ctx_lists_mux held.
 */
static void sefs_msg_ctx_free_to_alloc(struct sefs_msg_ctx *msg_ctx)
{
	list_move(&msg_ctx->node, &sefs_msg_ctx_alloc_list);
	msg_ctx->state = SEFS_MSG_CTX_STATE_PENDING;
	msg_ctx->counter = ++sefs_msg_counter;
}

/**
 * sefs_msg_ctx_alloc_to_free
 * @msg_ctx: The context to move from the alloc list to the free list
 *
 * Must be called with sefs_msg_ctx_lists_mux held.
 */
void sefs_msg_ctx_alloc_to_free(struct sefs_msg_ctx *msg_ctx)
{
	list_move(&(msg_ctx->node), &sefs_msg_ctx_free_list);
	kfree(msg_ctx->msg);
	msg_ctx->msg = NULL;
	msg_ctx->state = SEFS_MSG_CTX_STATE_FREE;
}

/**
 * sefs_find_daemon_by_euid
 * @daemon: If return value is zero, points to the desired daemon pointer
 *
 * Must be called with sefs_daemon_hash_mux held.
 *
 * Search the hash list for the current effective user id.
 *
 * Returns zero if the user id exists in the list; non-zero otherwise.
 */
int sefs_find_daemon_by_euid(struct sefs_daemon **daemon)
{
	int rc;

	hlist_for_each_entry(*daemon,
			    &sefs_daemon_hash[sefs_current_euid_hash()],
			    euid_chain) {
		if (uid_eq((*daemon)->file->f_cred->euid, current_euid())) {
			rc = 0;
			goto out;
		}
	}
	rc = -EINVAL;
out:
	return rc;
}

/**
 * sefs_spawn_daemon - Create and initialize a new daemon struct
 * @daemon: Pointer to set to newly allocated daemon struct
 * @file: File used when opening /dev/sefs
 *
 * Must be called ceremoniously while in possession of
 * sefs_sacred_daemon_hash_mux
 *
 * Returns zero on success; non-zero otherwise
 */
int
sefs_spawn_daemon(struct sefs_daemon **daemon, struct file *file)
{
	int rc = 0;

	(*daemon) = kzalloc(sizeof(**daemon), GFP_KERNEL);
	if (!(*daemon)) {
		rc = -ENOMEM;
		printk(KERN_ERR "%s: Failed to allocate [%zd] bytes of "
		       "GFP_KERNEL memory\n", __func__, sizeof(**daemon));
		goto out;
	}
	(*daemon)->file = file;
	mutex_init(&(*daemon)->mux);
	INIT_LIST_HEAD(&(*daemon)->msg_ctx_out_queue);
	init_waitqueue_head(&(*daemon)->wait);
	(*daemon)->num_queued_msg_ctx = 0;
	hlist_add_head(&(*daemon)->euid_chain,
		       &sefs_daemon_hash[sefs_current_euid_hash()]);
out:
	return rc;
}

/**
 * sefs_exorcise_daemon - Destroy the daemon struct
 *
 * Must be called ceremoniously while in possession of
 * sefs_daemon_hash_mux and the daemon's own mux.
 */
int sefs_exorcise_daemon(struct sefs_daemon *daemon)
{
	struct sefs_msg_ctx *msg_ctx, *msg_ctx_tmp;
	int rc = 0;

	mutex_lock(&daemon->mux);
	if ((daemon->flags & SEFS_DAEMON_IN_READ)
	    || (daemon->flags & SEFS_DAEMON_IN_POLL)) {
		rc = -EBUSY;
		mutex_unlock(&daemon->mux);
		goto out;
	}
	list_for_each_entry_safe(msg_ctx, msg_ctx_tmp,
				 &daemon->msg_ctx_out_queue, daemon_out_list) {
		list_del(&msg_ctx->daemon_out_list);
		daemon->num_queued_msg_ctx--;
		printk(KERN_WARNING "%s: Warning: dropping message that is in "
		       "the out queue of a dying daemon\n", __func__);
		sefs_msg_ctx_alloc_to_free(msg_ctx);
	}
	hlist_del(&daemon->euid_chain);
	mutex_unlock(&daemon->mux);
	kzfree(daemon);
out:
	return rc;
}

/**
 * sefs_process_reponse
 * @msg: The sefs message received; the caller should sanity check
 *       msg->data_len and free the memory
 * @seq: The sequence number of the message; must match the sequence
 *       number for the existing message context waiting for this
 *       response
 *
 * Processes a response message after sending an operation request to
 * userspace. Some other process is awaiting this response. Before
 * sending out its first communications, the other process allocated a
 * msg_ctx from the sefs_msg_ctx_arr at a particular index. The
 * response message contains this index so that we can copy over the
 * response message into the msg_ctx that the process holds a
 * reference to. The other process is going to wake up, check to see
 * that msg_ctx->state == SEFS_MSG_CTX_STATE_DONE, and then
 * proceed to read off and process the response message. Returns zero
 * upon delivery to desired context element; non-zero upon delivery
 * failure or error.
 *
 * Returns zero on success; non-zero otherwise
 */
int sefs_process_response(struct sefs_daemon *daemon,
			      struct sefs_message *msg, u32 seq)
{
	struct sefs_msg_ctx *msg_ctx;
	size_t msg_size;
	int rc;

	if (msg->index >= sefs_message_buf_len) {
		rc = -EINVAL;
		printk(KERN_ERR "%s: Attempt to reference "
		       "context buffer at index [%d]; maximum "
		       "allowable is [%d]\n", __func__, msg->index,
		       (sefs_message_buf_len - 1));
		goto out;
	}
	msg_ctx = &sefs_msg_ctx_arr[msg->index];
	mutex_lock(&msg_ctx->mux);
	if (msg_ctx->state != SEFS_MSG_CTX_STATE_PENDING) {
		rc = -EINVAL;
		printk(KERN_WARNING "%s: Desired context element is not "
		       "pending a response\n", __func__);
		goto unlock;
	} else if (msg_ctx->counter != seq) {
		rc = -EINVAL;
		printk(KERN_WARNING "%s: Invalid message sequence; "
		       "expected [%d]; received [%d]\n", __func__,
		       msg_ctx->counter, seq);
		goto unlock;
	}
	msg_size = (sizeof(*msg) + msg->data_len);
	msg_ctx->msg = kmemdup(msg, msg_size, GFP_KERNEL);
	if (!msg_ctx->msg) {
		rc = -ENOMEM;
		printk(KERN_ERR "%s: Failed to allocate [%zd] bytes of "
		       "GFP_KERNEL memory\n", __func__, msg_size);
		goto unlock;
	}
	msg_ctx->state = SEFS_MSG_CTX_STATE_DONE;
	wake_up_process(msg_ctx->task);
	rc = 0;
unlock:
	mutex_unlock(&msg_ctx->mux);
out:
	return rc;
}

/**
 * sefs_send_message_locked
 * @data: The data to send
 * @data_len: The length of data
 * @msg_ctx: The message context allocated for the send
 *
 * Must be called with sefs_daemon_hash_mux held.
 *
 * Returns zero on success; non-zero otherwise
 */
static int
sefs_send_message_locked(char *data, int data_len, u8 msg_type,
			     struct sefs_msg_ctx **msg_ctx)
{
	struct sefs_daemon *daemon;
	int rc;

	rc = sefs_find_daemon_by_euid(&daemon);
	if (rc) {
		rc = -ENOTCONN;
		goto out;
	}
	mutex_lock(&sefs_msg_ctx_lists_mux);
	rc = sefs_acquire_free_msg_ctx(msg_ctx);
	if (rc) {
		mutex_unlock(&sefs_msg_ctx_lists_mux);
		printk(KERN_WARNING "%s: Could not claim a free "
		       "context element\n", __func__);
		goto out;
	}
	sefs_msg_ctx_free_to_alloc(*msg_ctx);
	mutex_unlock(&(*msg_ctx)->mux);
	mutex_unlock(&sefs_msg_ctx_lists_mux);
	rc = sefs_send_miscdev(data, data_len, *msg_ctx, msg_type, 0,
				   daemon);
	if (rc)
		printk(KERN_ERR "%s: Error attempting to send message to "
		       "userspace daemon; rc = [%d]\n", __func__, rc);
out:
	return rc;
}

/**
 * sefs_send_message
 * @data: The data to send
 * @data_len: The length of data
 * @msg_ctx: The message context allocated for the send
 *
 * Grabs sefs_daemon_hash_mux.
 *
 * Returns zero on success; non-zero otherwise
 */
int sefs_send_message(char *data, int data_len,
			  struct sefs_msg_ctx **msg_ctx)
{
	int rc;

	mutex_lock(&sefs_daemon_hash_mux);
	rc = sefs_send_message_locked(data, data_len, SEFS_MSG_REQUEST,
					  msg_ctx);
	mutex_unlock(&sefs_daemon_hash_mux);
	return rc;
}

/**
 * sefs_wait_for_response
 * @msg_ctx: The context that was assigned when sending a message
 * @msg: The incoming message from userspace; not set if rc != 0
 *
 * Sleeps until awaken by sefs_receive_message or until the amount
 * of time exceeds sefs_message_wait_timeout.  If zero is
 * returned, msg will point to a valid message from userspace; a
 * non-zero value is returned upon failure to receive a message or an
 * error occurs. Callee must free @msg on success.
 */
int sefs_wait_for_response(struct sefs_msg_ctx *msg_ctx,
			       struct sefs_message **msg)
{
	signed long timeout = sefs_message_wait_timeout * HZ;
	int rc = 0;

sleep:
	timeout = schedule_timeout_interruptible(timeout);
	mutex_lock(&sefs_msg_ctx_lists_mux);
	mutex_lock(&msg_ctx->mux);
	if (msg_ctx->state != SEFS_MSG_CTX_STATE_DONE) {
		if (timeout) {
			mutex_unlock(&msg_ctx->mux);
			mutex_unlock(&sefs_msg_ctx_lists_mux);
			goto sleep;
		}
		rc = -ENOMSG;
	} else {
		*msg = msg_ctx->msg;
		msg_ctx->msg = NULL;
	}
	sefs_msg_ctx_alloc_to_free(msg_ctx);
	mutex_unlock(&msg_ctx->mux);
	mutex_unlock(&sefs_msg_ctx_lists_mux);
	return rc;
}

int __init sefs_init_messaging(void)
{
	int i;
	int rc = 0;

	if (sefs_number_of_users > SEFS_MAX_NUM_USERS) {
		sefs_number_of_users = SEFS_MAX_NUM_USERS;
		printk(KERN_WARNING "%s: Specified number of users is "
		       "too large, defaulting to [%d] users\n", __func__,
		       sefs_number_of_users);
	}
	mutex_init(&sefs_daemon_hash_mux);
	mutex_lock(&sefs_daemon_hash_mux);
	sefs_hash_bits = 1;
	while (sefs_number_of_users >> sefs_hash_bits)
		sefs_hash_bits++;
	sefs_daemon_hash = kmalloc((sizeof(struct hlist_head)
					* (1 << sefs_hash_bits)),
				       GFP_KERNEL);
	if (!sefs_daemon_hash) {
		rc = -ENOMEM;
		printk(KERN_ERR "%s: Failed to allocate memory\n", __func__);
		mutex_unlock(&sefs_daemon_hash_mux);
		goto out;
	}
	for (i = 0; i < (1 << sefs_hash_bits); i++)
		INIT_HLIST_HEAD(&sefs_daemon_hash[i]);
	mutex_unlock(&sefs_daemon_hash_mux);
	sefs_msg_ctx_arr = kmalloc((sizeof(struct sefs_msg_ctx)
					* sefs_message_buf_len),
				       GFP_KERNEL);
	if (!sefs_msg_ctx_arr) {
		rc = -ENOMEM;
		printk(KERN_ERR "%s: Failed to allocate memory\n", __func__);
		goto out;
	}
	mutex_init(&sefs_msg_ctx_lists_mux);
	mutex_lock(&sefs_msg_ctx_lists_mux);
	sefs_msg_counter = 0;
	for (i = 0; i < sefs_message_buf_len; i++) {
		INIT_LIST_HEAD(&sefs_msg_ctx_arr[i].node);
		INIT_LIST_HEAD(&sefs_msg_ctx_arr[i].daemon_out_list);
		mutex_init(&sefs_msg_ctx_arr[i].mux);
		mutex_lock(&sefs_msg_ctx_arr[i].mux);
		sefs_msg_ctx_arr[i].index = i;
		sefs_msg_ctx_arr[i].state = SEFS_MSG_CTX_STATE_FREE;
		sefs_msg_ctx_arr[i].counter = 0;
		sefs_msg_ctx_arr[i].task = NULL;
		sefs_msg_ctx_arr[i].msg = NULL;
		list_add_tail(&sefs_msg_ctx_arr[i].node,
			      &sefs_msg_ctx_free_list);
		mutex_unlock(&sefs_msg_ctx_arr[i].mux);
	}
	mutex_unlock(&sefs_msg_ctx_lists_mux);
	rc = sefs_init_sefs_miscdev();
	if (rc)
		sefs_release_messaging();
out:
	return rc;
}

void sefs_release_messaging(void)
{
	if (sefs_msg_ctx_arr) {
		int i;

		mutex_lock(&sefs_msg_ctx_lists_mux);
		for (i = 0; i < sefs_message_buf_len; i++) {
			mutex_lock(&sefs_msg_ctx_arr[i].mux);
			kfree(sefs_msg_ctx_arr[i].msg);
			mutex_unlock(&sefs_msg_ctx_arr[i].mux);
		}
		kfree(sefs_msg_ctx_arr);
		mutex_unlock(&sefs_msg_ctx_lists_mux);
	}
	if (sefs_daemon_hash) {
		struct sefs_daemon *daemon;
		struct hlist_node *n;
		int i;

		mutex_lock(&sefs_daemon_hash_mux);
		for (i = 0; i < (1 << sefs_hash_bits); i++) {
			int rc;

			hlist_for_each_entry_safe(daemon, n,
						  &sefs_daemon_hash[i],
						  euid_chain) {
				rc = sefs_exorcise_daemon(daemon);
				if (rc)
					printk(KERN_ERR "%s: Error whilst "
					       "attempting to destroy daemon; "
					       "rc = [%d]. Dazed and confused, "
					       "but trying to continue.\n",
					       __func__, rc);
			}
		}
		kfree(sefs_daemon_hash);
		mutex_unlock(&sefs_daemon_hash_mux);
	}
	sefs_destroy_sefs_miscdev();
	return;
}
