#ifndef _SLOT_HUB_H_
#define _SLOT_HUB_H_

#include <linux/input.h>
#include <linux/list.h>

typedef struct {
    void *identity;
    int slot_original;
    int slot_unite;
    int down_number;
    int slot_source;
    int tp_status;
    struct list_head identity_head;
    struct list_head algorithm_head;
} _information_t, *information_t;

typedef struct {
    void *identity;
    struct list_head slot_head;
    struct list_head list;
} _identity_node_t, *identity_node_t;

typedef struct {
    int slot_original;
    int slot_unite;
	int slot_source;
    struct list_head list;
} _slot_node_t, *slot_node_t;

#define TOUCH_DOWN_T 1
#define TOUCH_UP_T 2
#define MAX_TOUCH 9
#define ERRVEL -1

#endif