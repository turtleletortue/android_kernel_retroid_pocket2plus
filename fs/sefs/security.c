#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/highmem.h>

#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/types.h>	/* size_t */
#include <linux/proc_fs.h>
#include <linux/fcntl.h>	/* O_ACCMODE */
#include <linux/seq_file.h>
#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/device.h>

#include <linux/init.h>
#include <linux/uaccess.h>

#include <asm/uaccess.h>   // Needed by segment descriptors
#include <linux/mm.h>

#include <linux/sched.h>
#include <linux/sched/mm.h>
#include "security.h"		/* local definitions */

#define TRACE printk("%s %d\n",__func__,__LINE__);

#define CHECK_INIT 0
#define CHECK_FAIL 1
#define CHECK_PASS 2
#define DEBUG_MODE 1

//#define SEFS__DEBUG 

#ifdef SEFS__DEBUG
 #define EFS_DEBUG(...)  \
 	do {\
		printk(__VA_ARGS__); \
 	} \
 	while(0);
#else
 #define EFS_DEBUG(...)  \
        do {\
	   ;\
        } \
        while(0);
#endif

struct check_list{
	struct list_head list;
    int access_right;
	int valid_check;
	unsigned int crc32;
	int len;
	char f_name[256]; 
};

struct ac_list{
	struct list_head list;
	int pid;
};

struct efs_dev {
	struct list_head head;
	struct list_head access_allow_head;
	struct list_head pm_list;
	int open;
	int new_auth_event; 
	int check_valid_result; 
	int debug_mode; 
	spinlock_t lock;
	char* key_buffer;
	int key_len;
	struct cdev cdev;	  /* Char device structure		*/
};

extern int myaes_encrypt(unsigned char *in,unsigned char* out, int len);
extern int myaes_decrypt(unsigned char *in,unsigned char* out, int len);
extern int myaes_decrypt_key(unsigned char *key, unsigned char *in,unsigned char* out, int len);
extern unsigned int my_crc32(unsigned int crc,unsigned char *buffer, unsigned int size) ;
static char* get_file_buffer(char* path,loff_t* out_size);

static struct efs_dev *efs_devices;	/* allocated in efs_init_module */
static int efs_major =   0;
static int efs_minor =   0;

static unsigned int buffer_to_u32(unsigned char *buff)
{
	unsigned int data = 0;
	data |= (buff[0] << 24);
	data |= (buff[1] << 16);
	data |= (buff[2] << 8) ;
	data |=  buff[3];
	return  data;
}

#ifdef SEFS_DEBUG
inline  void myhexdump(unsigned char *buf,int len)
{
	if(len <= 0)
		return ;
	
	printk("myhexdump start %d:\n",len);
    while(len--)
        printk("myhexdump %02x\n",*buf++);
    printk("myhexdump end\n\n");
}
#endif
unsigned int get_factor1(void);

static int efs_parse(struct efs_dev *dev,unsigned char*buffer,int len)
{
	unsigned int count;
	int i = 0;
	unsigned char* dec_buffer;
	unsigned char *pos;
	unsigned int start_magic,end_magic;
	struct check_list *cl;
	unsigned int factor;
	unsigned int temp;
	unsigned short *pval;
	unsigned char* key;
	unsigned char* buffer2;
	loff_t fsize;

	buffer2 = (unsigned char*)get_file_buffer("/system/lib/libthermal.so",&fsize);
	if(buffer2 == 0)
		return -1;
	
	// des dec
	dec_buffer = kmalloc(fsize, GFP_KERNEL);
	if(!dec_buffer)
	{
		kfree(buffer2);
		return -1;
	}

	key = kmalloc(32, GFP_KERNEL);
	if(!key)
	{
		kfree(buffer2);
		kfree(dec_buffer);
		return -1;
	}
	
	factor = 0x113c2a50;
	for(i = 0; i<16; i++)
	{
		pval = (unsigned short *)(key + i*2);
		temp = (unsigned int)int_sqrt(((factor>>i)&0xffff)*((factor>>i)&0xffff)+
			                           (((~factor<<i)&0xffff0000)>>16)*(((~factor<<i)&0xffff0000)>>16));
		*pval = temp & 0xffff;
	}
	
#ifdef DUMP_KEY
	myhexdump(key,32);
#endif
	
	myaes_decrypt_key(key, buffer2, dec_buffer, fsize);
	kfree(buffer2);
	kfree(key);

	// parse list to make a list_head
	pos = dec_buffer;
	start_magic = buffer_to_u32(pos); 
	pos += 4;
	if(start_magic != 0x23476812)
	{
		EFS_DEBUG("sefs kill  start_magic:%x \n",start_magic);
		//TRACE;
		dev->check_valid_result = CHECK_FAIL;
		kfree(dec_buffer);
		return -1;
	}

	count = buffer_to_u32(pos); pos += 12;
	//printk("<1>sefs count:%d \n",count);
	
	for( i = 0; i<count; i++)
	{
		cl = kmalloc(sizeof(struct check_list),GFP_KERNEL);
		if(!cl)
		{
			kfree(dec_buffer);
			return -1;
		}
		memset(cl,0,sizeof(struct check_list));
		cl->valid_check = buffer_to_u32(pos); pos += 4;
		cl->access_right = buffer_to_u32(pos); pos += 4;
		cl->crc32 = buffer_to_u32(pos); pos += 4;
		cl->len = buffer_to_u32(pos); pos += 4;
		memcpy(cl->f_name,pos,cl->len); pos += cl->len;
		list_add_tail(&cl->list,&dev->head);
		EFS_DEBUG("sefs crc32:0x%x    f_name:%s    valid_check:%d    access_right:%d\n",cl->crc32,cl->f_name,cl->valid_check,cl->access_right);
	}

	end_magic = buffer_to_u32(pos); pos += 4;
	if(end_magic != 0x75914757)
	{
		EFS_DEBUG("<1>sefs kill  end_magic:%x \n",end_magic);
		//TRACE;
		dev->check_valid_result = CHECK_FAIL;
		kfree(dec_buffer);
		return -1;
	}

	dev->check_valid_result = CHECK_PASS;
	kfree(dec_buffer);
	return 0;
}


// check app valid user crc 
static int efs_node_check_vaild(struct check_list *node)
{
	loff_t len;
	loff_t ret;
	struct file *f;
	mm_segment_t fs;
	unsigned char *buffer;
	unsigned int crc = 0xffffffff;
	int valid_check_resule = 0;
	
	f = filp_open(node->f_name, O_RDONLY, 0644);
	if (IS_ERR(f)){
        return 0;
    }

	buffer = kmalloc(4096,GFP_KERNEL);
	if(!buffer)
	{
		filp_close(f,NULL);
		return 0;
	}

	fs = get_fs();
    set_fs(KERNEL_DS);
	
	vfs_llseek(f,0,SEEK_END);
	len = vfs_llseek(f,0,SEEK_CUR);
	vfs_llseek(f,0,SEEK_SET);

	while(f->f_pos != len)
	{
		ret = vfs_read(f, buffer, 4096, &f->f_pos);
		if(ret == 0)
			break;
		else if(ret < 0)
			msleep(20);
		crc = my_crc32(crc,buffer,ret);
	}
	kfree(buffer);
	// Restore segment descriptor
	set_fs(fs);

	filp_close(f,NULL);
	crc = ~crc;
	valid_check_resule = (crc == node->crc32) ? 1 : 0;
	EFS_DEBUG("sefs valid_check_resule:%d    crc:%x    node->crc32:%x\n",valid_check_resule,crc,node->crc32);
	return valid_check_resule;
}

// check app valid user crc 
static char* get_file_buffer(char* path,loff_t* out_size)
{
	loff_t len = 0;
	loff_t ret;
	loff_t total_len;
	struct file *f;
	mm_segment_t fs;
	char *buffer;
	
	f = filp_open(path, O_RDONLY, 0644);
	if (IS_ERR(f)){
		//printk("get_txt open %s fail\n",path);
        return 0;
    }

	fs = get_fs();
    set_fs(KERNEL_DS);
	vfs_llseek(f,0,SEEK_END);
	total_len = vfs_llseek(f,0,SEEK_CUR);
	vfs_llseek(f,0,SEEK_SET);

	buffer = kmalloc(total_len,GFP_KERNEL);
	if(!buffer)
	{
		set_fs(fs);
		filp_close(f,NULL);
		return 0;
	}
	*out_size = total_len;
	memset(buffer,0,total_len);
	while(len != total_len)
	{
		ret = vfs_read(f, buffer + len, total_len, &f->f_pos);
		if(ret == 0)
			break;
		len += ret;
	}
	// Restore segment descriptor
	set_fs(fs);

	filp_close(f,NULL);
	//printk("sefs get_txt %s\n",buffer);
	
	return buffer;

}


static char* get_txt(char* path)
{
	loff_t len = 0;
	loff_t ret;
	loff_t total_len;
	struct file *f;
	mm_segment_t fs;
	char *buffer;
	
	f = filp_open(path, O_RDONLY, 0644);
	if (IS_ERR(f)){
		//printk("get_txt open %s fail\n",path);
        return 0;
    }

	buffer = kmalloc(256,GFP_KERNEL);
	if(!buffer)
	{
		filp_close(f,NULL);
		return 0;
	}
	memset(buffer,0,256);
	fs = get_fs();
    set_fs(KERNEL_DS);

	total_len = 256;

	while(len != total_len)
	{
		ret = vfs_read(f, buffer + len, total_len, &f->f_pos);
		if(ret == 0)
			break;
		len += ret;
	}
	// Restore segment descriptor
	set_fs(fs);

	filp_close(f,NULL);
	//printk("sefs get_txt %s\n",buffer);
	
	return buffer;
}

static void efs_self_cheak(struct efs_dev *dev)
{
	struct list_head *head = &dev->head;
	struct list_head *plist,*n;
	struct check_list *node = 0;
	int found = 0;
	char *txt;
	char path[64] = {0};
	
	sprintf(path,"/proc/%d/cmdline",current->pid);
	txt = get_txt(path);
	//printk("sefs efs_self_cheak %s  %x\n",txt,path);
	list_for_each_safe(plist,n,head)
	{
		node = list_entry(plist, struct check_list, list);
		if(/*node->valid_check && */txt)
		{
			if(strcmp(node->f_name,txt) == 0)
			{
				found = 1;
				break;
			}
		}
	}
	if(txt)
		kfree(txt);
	if(found)
		dev->check_valid_result = CHECK_PASS;
	else
		dev->check_valid_result = CHECK_FAIL;
}

static void efs_check_valid_start(struct efs_dev *dev)
{
	// check app valid
	struct list_head *head = &dev->head;
	struct list_head *plist,*n;
	struct check_list *node = 0;
	int ret = 1;

	list_for_each_safe(plist,n,head)
	{
		node = list_entry(plist, struct check_list, list);
		if(strcmp(node->f_name,"debug_mode_v3") == 0)
		{
			EFS_DEBUG("sefs this is debug\n");
			dev->debug_mode = DEBUG_MODE;
			return;
		}
	}
	
	//printk("<1>sefs start\n");
	list_for_each_safe(plist,n,head)
	{
		node = list_entry(plist, struct check_list, list);
		if(node->valid_check)
		{
			ret = efs_node_check_vaild(node);
			if(ret != 1)
			{
				EFS_DEBUG("sefs check %s fail\n",node->f_name);
				dev->check_valid_result = CHECK_FAIL;
				return;
			}
		}
	}

	dev->check_valid_result = CHECK_PASS;
}

static void efs_clean(struct efs_dev *dev)
{
	struct list_head *head = &dev->head;
	struct list_head *access_allow_head = &dev->access_allow_head;
	struct list_head *plist,*n;
	struct check_list *cl = 0;
	struct ac_list    *ac = 0;
	struct list_head  ac_clean;
	struct pm_list    *pl;
	
	list_for_each_safe(plist,n,head)
	{
		cl = list_entry(plist, struct check_list, list);
		list_del(&cl->list);
		kfree(cl);
	}

	dev->open = 0;
	dev->check_valid_result = CHECK_INIT;
	dev->debug_mode = 0;
	if(dev->key_len != -1)
	{
		kfree(dev->key_buffer);
		dev->key_len = -1;
	}

	INIT_LIST_HEAD(&ac_clean);
	spin_lock(&dev->lock);
	list_for_each_safe(plist,n,access_allow_head)
	{
		ac = list_entry(plist, struct ac_list, list);
		list_del(&ac->list);
		list_add(&ac->list,&ac_clean);
	}
	spin_unlock(&dev->lock);
	
	list_for_each_safe(plist,n,&ac_clean)
	{
		ac = list_entry(plist, struct ac_list, list);
		list_del(&ac->list);
		kfree(ac);
	}

	list_for_each_safe(plist,n,&dev->pm_list)
	{
		pl = list_entry(plist, struct pm_list, list);
		list_del(&pl->list);
		kfree(pl);
	}
}

static int efs_pid_cmdline(struct task_struct *task, char * buffer)
{
	int res = 0;
	unsigned int len;
	struct mm_struct *mm = get_task_mm(task);
	if (!mm)
		goto out;
	if (!mm->arg_end)
		goto out_mm;	/* Shh! No looking before we're done */

 	len = mm->arg_end - mm->arg_start;
 
	if (len > PAGE_SIZE)
		len = PAGE_SIZE;
 
	res = access_process_vm(task, mm->arg_start, buffer, len, 0);

	// If the nul at the end of args has been overwritten, then
	// assume application is using setproctitle(3).
	if (res > 0 && buffer[res-1] != '\0' && len < PAGE_SIZE) {
		len = strnlen(buffer, res);
		if (len < res) {
		    res = len;
		} else {
			len = mm->env_end - mm->env_start;
			if (len > PAGE_SIZE - res)
				len = PAGE_SIZE - res;
			res += access_process_vm(task, mm->env_start, buffer+res, len, 0);
			res = strnlen(buffer, res);
		}
	}
out_mm:
	mmput(mm);
out:
	return res;
}

int efs_check_path(struct list_head * cl_head,struct list_head * pm_head)
{
	struct list_head *plist,*n;
	struct check_list *cl_node = 0;
	struct pm_list *pm_node = 0;
	char *abs_path = 0;
	char *txt = 0;
	int i = 0;

	txt = kmalloc(4096,GFP_KERNEL);
	if(!txt)
		return -1;
	memset(txt,0,4096);
	efs_pid_cmdline(current,txt);
	//printk("sefs efs_check_path:%s\n",txt);
	if(txt[0] == '\0')
	{
		kfree(txt);
		return -1;
	}

	for(i = 0; i<256; i++)
	{
		if(txt[i] == 0x20) // is space
		{
			txt[i] = '\0';
			i++;
			break;
		}
	}

	if(txt[0] == '/')     // only allow absolute path access
		abs_path = txt;
	else  // guess maybe apk
	{
		list_for_each_safe(plist,n,pm_head)
		{
			pm_node = list_entry(plist, struct pm_list, list);
			//printk("sefs efs_check_path  guess maybe apk,checking: %s\n",pm_node->package_name);
			if(strncmp(pm_node->package_name,txt,i) == 0)
			{
				abs_path = pm_node->absolute_path;
				break;
			}
		}
		if(abs_path == 0)
		{
			///printk("sefs efs_check_path  %s not absolute path or apk\n",txt);
			kfree(txt);
			return -1;
		}
	}

	list_for_each_safe(plist,n,cl_head)
	{
		cl_node = list_entry(plist, struct check_list, list);
		if(strncmp(cl_node->f_name, abs_path, i) == 0)
		{
			//printk("sefs efs_check_path  allow:%s\n",abs_path);
			kfree(txt);
			return 0;
		}
	}

	//printk("sefs efs_check_path  not allow:%s\n",abs_path);
	kfree(txt);
	return -1;
}

int efs_check(int pid)
{
	struct efs_dev *dev = efs_devices;
	struct list_head *access_allow_head = &dev->access_allow_head;
	struct list_head *plist,*n;
	struct ac_list *node = 0;

	if(dev == 0)
		return -1;

	if(dev->debug_mode == DEBUG_MODE)
		return 0;

	if(dev->check_valid_result != CHECK_PASS || dev->open == 0)
		return -1;

	spin_lock(&dev->lock);
	list_for_each_safe(plist,n,access_allow_head)
	{
		node = list_entry(plist, struct ac_list, list);
		if(node->pid == pid)
		{
			spin_unlock(&dev->lock);
			return 0;
		}
	}
	spin_unlock(&dev->lock);

	if(efs_check_path(&dev->head, &dev->pm_list) == -1)
		return -1;

	node = kmalloc(sizeof(struct ac_list),GFP_KERNEL);
	if(!node)
		return -1;
	memset(node,0,sizeof(struct ac_list));
	node->pid = pid;
	spin_lock(&dev->lock);
	list_add(&node->list,access_allow_head);
	spin_unlock(&dev->lock);
	dev->new_auth_event++;
	return 0;
}


// app clean old pid
static int efs_clean_old_node(struct efs_dev *dev,int *pid,int count)
{
	struct list_head *access_allow_head = &dev->access_allow_head;
	struct list_head *plist,*n;
	struct ac_list *node = 0;
	int i = 0;
	int found = 0;
	int auth_count = 0;
	struct list_head old;

	//for(i = 0; i<count; i++)
	//{
	//	printk("sefs new ps list pid[%d]:%d\n",i,pid[i]);
	//}
	
	INIT_LIST_HEAD(&old);
	spin_lock(&dev->lock);
	list_for_each_safe(plist,n,access_allow_head)
	{
		node = list_entry(plist, struct ac_list, list);
		found = 0;
		auth_count++;
		for(i = 0; i<count; i++)
		{
			if(node->pid == pid[i])
			{
				found = 1;
				break;
			}
		}
		
		if(found == 0)
		{
			list_del(&node->list);
			list_add(&node->list,&old);
		}
	}
	spin_unlock(&dev->lock);
	
	list_for_each_safe(plist,n,&old)
	{
		node = list_entry(plist, struct ac_list, list);
		//printk("sefs clean pid:%d\n",node->pid);
		list_del(&node->list);
		kfree((void*)node);
	}

	//printk("sefs  auth_count:%d\n",auth_count);

	return 0;

}

static int efs_open(struct inode *inode, struct file *filp)
{
	struct efs_dev *dev; /* device information */
		
	dev = container_of(inode->i_cdev, struct efs_dev, cdev);
	filp->private_data = dev; /* for other methods */
	if(dev->open != 0)
		return -ENOMEM;
	dev->open = 1;
	
	//printk("sefs efs_open (pid=%d, comm=%s)\n", current->pid, current->comm);
	return 0;          /* success */
}

static ssize_t efs_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
	int len;
	char* buffer;
	int err;
	
	struct efs_dev *dev = filp->private_data;
		
	err = copy_from_user( &len, (void __user *)buf, 4);
	buffer = (char*)kmalloc(len, GFP_KERNEL);
	if(buffer == 0)
		return -ENOMEM;
	err = copy_from_user(buffer, (void __user *)(buf+4), len);
	dev->key_buffer = buffer;
	dev->key_len = len;
	return count;
}

static ssize_t efs_read(struct file *filp, char __user *buf, size_t count,loff_t *f_pos)
{
	return count;
}

static int efs_release(struct inode *inode, struct file *filp)
{
	struct efs_dev *dev = filp->private_data;
	efs_clean(dev);
	//printk("<1>sefs efs_release\n");
	return 0;
}

static long efs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int err = 0;
    int ret = 0;
	struct efs_dev *dev = filp->private_data;
	
    if (_IOC_TYPE(cmd) != EFS_IOC_MAGIC) 
        return -EINVAL;
	
    if (_IOC_NR(cmd) > EFS_IOC_MAXNR) 
        return -ENFILE;

    if (_IOC_DIR(cmd) & _IOC_READ)
        err = !access_ok(VERIFY_WRITE, (void *)arg, _IOC_SIZE(cmd));
    else if (_IOC_DIR(cmd) & _IOC_WRITE)
        err = !access_ok(VERIFY_READ, (void *)arg, _IOC_SIZE(cmd));
    if (err) 
        return -EFAULT;

    switch(cmd) {
      case EFS_IOC_START_CHECK: 
      	{
      		efs_parse(dev,dev->key_buffer,dev->key_len);
			if(dev->check_valid_result != CHECK_PASS)
			{
				EFS_DEBUG("sefs parse fail\n");
				return -ENOMEM;
			}

			efs_check_valid_start(dev);
			if(dev->debug_mode == 0 && dev->check_valid_result != CHECK_PASS)
			{
				EFS_DEBUG("sefs check valid fail\n");
				return -ENOMEM;
			}
			
		
			efs_self_cheak(dev);
			if(dev->debug_mode == 0 && dev->check_valid_result != CHECK_PASS)
			{
				EFS_DEBUG("sefs self cheak fail\n");
				return -ENOMEM;
			}
			kfree(dev->key_buffer);
			dev->key_len = -1;
      	}
        break;
	  
	  case EFS_IOC_CHECK_RUNTIME: 
      	{
			if(dev->debug_mode == 0)
			{
				if(dev->check_valid_result != CHECK_PASS)
					return -ENOMEM;
			}else
				break;
				
			efs_check_valid_start(dev);
			if(dev->debug_mode == 0 && dev->check_valid_result != CHECK_PASS)
			{
				EFS_DEBUG("sefs check valid fail\n");
				return -ENOMEM;
			}
			efs_self_cheak(dev);
			if(dev->debug_mode == 0 && dev->check_valid_result != CHECK_PASS)
			{
				EFS_DEBUG("sefs self cheak fail\n");
				return -ENOMEM;
			}
      	}
        break;
	  
      case EFS_IOC_GET_KEY:
      	{
      		unsigned char fpga_key[16];
			unsigned char rkey[16];
			unsigned int value;
			
			if(dev->debug_mode == 0 && dev->check_valid_result != CHECK_PASS)
				return -ENOMEM;
		  	err = copy_from_user( fpga_key, (void __user *)arg, 16);
			value = (fpga_key[8]<<16) | (fpga_key[9]<<8) | fpga_key[10];
			myaes_encrypt( fpga_key, rkey,16);
			if(value != 3616821)
				rkey[10] = 0xfa;
	        err = copy_to_user((void __user *)arg, rkey, 16);
      	}
        break;
	  
	  case EFS_IOC_GET_AUTH_EVENT:
      	{	
			if(dev->debug_mode == 0 && dev->check_valid_result != CHECK_PASS)
				return -ENOMEM;
	        err = copy_to_user((void __user *)arg, &dev->new_auth_event, 4);
			dev->new_auth_event = 0;
      	}
        break;
	  
	  case EFS_IOC_CLEAN_OLD_PID:
      	{
      		int len;
			int * pid_array;
		  	err = copy_from_user( &len, (void __user *)arg, 4);
		    pid_array = kmalloc(len, GFP_KERNEL);
			if(pid_array == 0)
				return -EINVAL;
			err = copy_from_user(pid_array, (void __user *)(arg+4), len);
			efs_clean_old_node(dev,pid_array,len/4);
			kfree(pid_array);
      	}
        break;
	  
	  case EFS_IOC_SET_PM_LIST:
      	{
      		struct pm_list *node;
      		if(dev->debug_mode == 0 && dev->check_valid_result != CHECK_PASS)
				return -ENOMEM;
		    node = kmalloc(sizeof(struct pm_list), GFP_KERNEL);
			if(node == 0)
				return -ENOMEM;
			err = copy_from_user(node, (void __user *)(arg), sizeof(struct pm_list));
			list_add(&node->list, &dev->pm_list);
			//printk("sefs EFS_IOC_SET_PM_LIST  %s  %s\n",node->package_name,node->absolute_path);
      	}
        break;
	  
      default:  
        return -EINVAL;
    }
	
    return ret;
}

static struct file_operations efs_fops = {
	.owner =    THIS_MODULE,
	.llseek =   no_llseek,
	.read =     efs_read,
	.write =    efs_write,
	.compat_ioctl  =    efs_ioctl,
	.open =     efs_open,
	.release =  efs_release,
};

static struct class *efs_class;
static struct device *efsdrv_device;
#if 0
static ssize_t
debug_store(struct device *pdev, struct device_attribute *attr,
			       const char *buff, size_t size)
{
	char buf[64], *b;
	char buf2[64] = {0};
	strlcpy(buf, buff, sizeof(buf));
	b = strim(buf);
	sprintf(buf2,"%d",efs_devices->key_len);
	if(strcmp(b,buf2) == 0)
		g_debug = 1;
	else
		g_debug = 0;
	
	//printk("sefs debug_store:%s len:%ld keyfile_size:%d\n",b,len,keyfile_size);
	return size;
}

static DEVICE_ATTR(value, S_IRUGO | S_IWUSR, NULL,
						 debug_store);
#endif
static void efs_setup_cdev(struct efs_dev *dev, int index)
{
	int err, devno = MKDEV(efs_major, efs_minor + index);
    
	cdev_init(&dev->cdev, &efs_fops);
	dev->cdev.owner = THIS_MODULE;
	dev->cdev.ops = &efs_fops;
	err = cdev_add (&dev->cdev, devno, 1);
	/* Fail gracefully if need be */
	//if (err)
	//	printk(KERN_NOTICE "Error %d adding efs%d", err, index);
}
#if 0
static struct device_attribute *sefs_attributes[] = {
	&dev_attr_value,
	NULL
};

#endif
void efs_cleanup_module(void)
{
	dev_t devno = MKDEV(efs_major, efs_minor);
	efs_clean(efs_devices);
	if (efs_devices) {
		cdev_del(&efs_devices->cdev);
		kfree(efs_devices);
		efs_devices = 0;
	}
	unregister_chrdev_region(devno, 1);
	device_unregister(efsdrv_device);  
	class_destroy(efs_class);
}

int efs_init_module(void)
{
	int result;
	dev_t dev = 0;
	struct efs_dev * pdev;
	//struct device_attribute **attrs = sefs_attributes;
	//struct device_attribute *attr;
	//int err;
		
	if (efs_major) {
		dev = MKDEV(efs_major, efs_minor);
		result = register_chrdev_region(dev, 1, "efs");
	} else {
		result = alloc_chrdev_region(&dev, efs_minor, 1,"efs");
		efs_major = MAJOR(dev);
	}
	if (result < 0) {
		return result;
	}

	pdev = kmalloc( sizeof(struct efs_dev), GFP_KERNEL);
	if (!pdev) {
		result = -ENOMEM;
		goto fail;  /* Make this more graceful */
	}
	memset(pdev, 0, sizeof(struct efs_dev));
	efs_setup_cdev(pdev,0);
	INIT_LIST_HEAD(&pdev->head);
	INIT_LIST_HEAD(&pdev->access_allow_head);
	INIT_LIST_HEAD(&pdev->pm_list);
	spin_lock_init(&pdev->lock);
	pdev->check_valid_result = CHECK_INIT;
	pdev->key_len = -1;
	efs_devices = pdev;

	efs_class = class_create(THIS_MODULE, "sefs");
	efsdrv_device = device_create(efs_class, NULL, MKDEV(efs_major, 0), NULL, "efs");
#if 0
	while ((attr = *attrs++)) {
		err = device_create_file(efsdrv_device, attr);
		if (err) {
			device_destroy(efs_class, efsdrv_device->devt);
			return err;
		}
	}
#endif	
	printk(KERN_EMERG "sefs efs_major:%d\n", efs_major);
	return 0; /* succeed */

  fail:
	efs_cleanup_module();
	return result;
}

MODULE_LICENSE("GPL");

