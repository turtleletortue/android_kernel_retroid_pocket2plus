
#ifndef _EFS_H_
#define _EFS_H_

#include <linux/ioctl.h> /* needed for the _IOW etc stuff used later */


#define EFS_IOC_MAGIC  'k'

#define EFS_IOCPRINT                 _IO(EFS_IOC_MAGIC, 1)
#define EFS_IOC_TEST                 _IOR(EFS_IOC_MAGIC, 2, int)
#define EFS_IOC_PARSE_DATA           _IOW(EFS_IOC_MAGIC, 3, int)
#define EFS_IOC_START_CHECK          _IOW(EFS_IOC_MAGIC, 4, int)
#define EFS_IOC_GET_KEY              _IOWR(EFS_IOC_MAGIC, 5, int)
#define EFS_IOC_REQUEST_EVENT        _IOWR(EFS_IOC_MAGIC, 6, int)
#define EFS_IOC_SET_PATH             _IOW(EFS_IOC_MAGIC, 7, int)
#define EFS_IOC_CLEAN_OLD_PID        _IOW(EFS_IOC_MAGIC, 8, int)
#define EFS_IOC_SET_PM_LIST          _IOW(EFS_IOC_MAGIC, 9, int)
#define EFS_IOC_GET_AUTH_EVENT       _IOR(EFS_IOC_MAGIC, 10, int)
#define EFS_IOC_CHECK_RUNTIME        _IOWR(EFS_IOC_MAGIC, 11, int)


#define EFS_IOC_MAXNR 100

struct event_info{
	unsigned long long node_handle ;
	int pid ;
};

struct proc_result{
	unsigned long long node_handle;
	int pid ;
	char path[256];
};

struct pm_list{
	struct list_head list;
	char package_name[256];
	char absolute_path[256];
};

struct security_info{
	int efs_fd;
	char rkey[16];
};

extern int  efs_init_module(void);
extern void efs_cleanup_module(void);
extern int  efs_check(int pid);

#endif /* _EFS_H_ */
