/*
 * SPRD external modem control driver in AP side.
 *
 * Copyright (C) 2019 Spreadtrum Co., Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 of
 * the License as published by the Free Software Foundation.
 *
 * This program is used to control external modem in AP side for
 * Spreadtrum SoCs.
 */

#ifndef SPRD_MODEM_LOADER_H
#define SPRD_MODEM_LOADER_H

/* modem region data define */
#define MAX_REGION_NAME_LEN	20
#define MAX_REGION_CNT		20

#ifdef CONFIG_SPRD_EXT_MODEM
/* modem remote flag */
#define IDEL_FLAG		0x0
#define REMOTE_DDR_READY_FLAG	BIT(0)
#define MODEM_IMAGE_DONE_FLAG	BIT(1)
#define MINIAP_IMAGE_DONE_FLAG	BIT(2)
#define MINIAP_PANIC_FLAG	BIT(3)
#define MINIAP_RESERVE_FLAG	BIT(4)
#define SPL_IMAGE_DONE_FLAG	BIT(5)
#endif

/* soc modem define */
#define MODEM_INVALID_REG	0xff
enum {
	MODEM_CTRL_SHUT_DOWN = 0,
	MODEM_CTRL_DEEP_SLEEP,
	MODEM_CTRL_CORE_RESET,
	MODEM_CTRL_SYS_RESET,
	MODEM_CTRL_GET_STATUS,
	MODEM_CTRL_NR
};

struct modem_region_info {
	u64	address;
	u32	size;
	char	name[MAX_REGION_NAME_LEN + 1];
};

struct modem_load_info {
	u32	region_cnt;
	u64	modem_base;
	u32	modem_size;
	u64	all_base;
	u32	all_size;
	struct modem_region_info	regions[MAX_REGION_CNT];
};

struct modem_ctrl {
	u32	ctrl_reg[MODEM_CTRL_NR];	/* offset value*/
	u32	ctrl_mask[MODEM_CTRL_NR];	/* mask bit */
	u32	ctrl_type[MODEM_CTRL_NR];	/* pmu or apb, 0 apb, 1 pmu */
	struct regmap *ctrl_map[MODEM_CTRL_NR];
};

struct modem_device {
	struct modem_load_info	*load;
	const char		*modem_name;
	struct modem_ctrl	*modem_ctrl;

#ifdef CONFIG_SPRD_EXT_MODEM_POWER_CTRL
	struct gpio_desc	*modem_reset;
	struct gpio_desc	*modem_power;
#endif

#ifdef CONFIG_DEBUG_FS
struct dentry	*debug_file;
#endif

	u8	read_region;
	u8	write_region;
	u8	run_state;
	u8	modem_type;	/* pcie, soc */

	u32	read_pose;
	u32	write_pose;
	u32	remote_flag;

	phys_addr_t	modem_base;
	size_t		modem_size;
	phys_addr_t	all_base;
	size_t		all_size;

	struct mutex	rd_mutex;/* mutex for read lock */
	struct mutex	wt_mutex;/* mutex for write lock */
	char	rd_lock_name[TASK_COMM_LEN];
	char	wt_lock_name[TASK_COMM_LEN];

	struct wakeup_source	rd_ws;
	struct wakeup_source	wt_ws;

	struct device	*p_dev;
	dev_t		devid;
	struct cdev	cdev;
};

struct ext_modem_operations {
	void (*get_remote_flag)(struct modem_device *modem);
	void (*set_remote_flag)(struct modem_device *modem, u8 b_clear);

#ifdef CONFIG_SPRD_EXT_MODEM_POWER_CTRL
	int (*reboot)(struct modem_device *modem, u8 b_reset);
	int (*poweroff)(struct modem_device *modem);
#endif
};

#ifdef CONFIG_SPRD_EXT_MODEM
void modem_get_ext_modem_ops(const struct ext_modem_operations **ops);
#endif

#ifndef CONFIG_SPRD_SIPC_V2
#define SOC_MODEM	0
#define modem_ram_vmap_nocache(type, start, size) \
	shmem_ram_vmap_nocache((start), (size))
#define modem_ram_unmap(type, mem)	shmem_ram_unmap((mem))
#endif

#endif
