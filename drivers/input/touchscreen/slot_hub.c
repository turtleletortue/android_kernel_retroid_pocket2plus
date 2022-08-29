#include "slot_hub.h"
#include <linux/slab.h>
#include <linux/mutex.h>

static information_t hub_information;

static slot_node_t create_slot_node(int slot_source, int slot_original, int slot_unite)
{
    slot_node_t slot_node = (slot_node_t)kzalloc(sizeof(_slot_node_t), GFP_KERNEL);
	slot_node->slot_original = slot_original;
	slot_node->slot_unite = slot_unite;
    slot_node->slot_source = slot_source;
    return slot_node;
}

static identity_node_t create_identity_node(void *identity)
{
    identity_node_t identity_node = (identity_node_t)kzalloc(sizeof(_identity_node_t), GFP_KERNEL);
	identity_node->identity = identity;
    INIT_LIST_HEAD(&identity_node->slot_head);
    return identity_node;
}

static slot_node_t search_slot(information_t information)
{
    slot_node_t slot_node = NULL;
    struct list_head *slot_list, *n_a;
    // identity_node_t identity_node = NULL;
    // struct list_head *identity_list, *slot_list, *n_a, *n_b;
    
/*
    list_for_each_safe(identity_list, n_a, &information->identity_head) {
        identity_node = list_entry(identity_list, _identity_node_t, list);
        if (identity_node->identity == information->identity) {
            list_for_each_safe(slot_list, n_b, &identity_node->slot_head) {
                slot_node = list_entry(slot_list, _slot_node_t, list);
                if (slot_node->slot_source == information->slot_source
                    && slot_node->slot_original == information->slot_original)
                    return slot_node;
            }
        }
    }
*/
    list_for_each_safe(slot_list, n_a, &information->algorithm_head) {
        slot_node = list_entry(slot_list, _slot_node_t, list);
        if (slot_node->slot_original == information->slot_original) {
            return slot_node;
        }
    }

    return NULL;
}

static void insert_node_in_root(information_t information)
{
    struct list_head *identity_list, *slot_list, *n;
    identity_node_t identity_node = NULL, node = NULL;
    slot_node_t slot_node = NULL;
    /* search in root list to find the equel identity */
    list_for_each_safe(identity_list, n, &information->identity_head) {
        node = list_entry(identity_list, _identity_node_t, list);
        if (node->identity == information->identity) {
            identity_node = node;
            break;
        }
    }

    /* when root list don't exit identity list */
    if (identity_node == NULL) {
        identity_node = create_identity_node(information->identity);
        list_add_tail(&identity_node->list, &information->identity_head);

        slot_node = create_slot_node(information->slot_source, information->slot_original, information->slot_unite);
        list_add_tail(&slot_node->list, &identity_node->slot_head);
        return;
    }

    /* there are identity list in the root list and slot node already exist */
    list_for_each_safe(slot_list, n, &identity_node->slot_head) {
        slot_node = list_entry(slot_list, _slot_node_t, list);
        if (slot_node->slot_unite == information->slot_unite
            && slot_node->slot_original == information->slot_original
            && slot_node->slot_source == information->slot_source) {
            return;
        }
    }

    /* there are identity list in the root list and slot node not exist */
    slot_node = create_slot_node(information->slot_source, information->slot_original, information->slot_unite);
    list_add_tail(&slot_node->list, &identity_node->slot_head);

    return;
}

static int delete_slot_node(information_t information)
{
    struct list_head *slot_list, *n;
    slot_node_t slot_node = NULL;

    slot_node = search_slot(information);
    if (slot_node != NULL) {
        information->slot_unite = slot_node->slot_unite;
        list_del(&slot_node->list);
        kfree(slot_node);
    } else {
        return ERRVEL;
    }

    list_for_each_safe(slot_list, n, &information->algorithm_head) {
        slot_node = list_entry(slot_list, _slot_node_t, list);
        if (slot_node->slot_unite == information->slot_unite
            && slot_node->slot_original == information->slot_original
            && slot_node->slot_source == information->slot_source) {
            list_del(&slot_node->list);
            kfree(slot_node);
        }
    }

    return information->slot_unite;
}

static int delete_identity_node(information_t information)
{
    struct list_head *identity_list, *n;
    identity_node_t identity_node = NULL;

    list_for_each_safe(identity_list, n, &information->identity_head) {
        identity_node = list_entry(identity_list, _identity_node_t, list);
        if (list_empty_careful(&identity_node->slot_head)) {
            list_del(&identity_node->list);
            kfree(identity_node);
        }
    }

    return true;
}

/**
*   function name : 
*               delete_identity_list
*   return : 
*               Return one undeleted slot at a time.
*               -1 indicates that the ideintity linked list is empty
*/
static int delete_identity_list(information_t information)
{
    struct list_head *identity_list, *slot_list, *n_a, *n_b, *n_c;
    identity_node_t identity_node = NULL;
    slot_node_t slot_node = NULL;
    int slot;

    list_for_each_safe(identity_list, n_a, &information->identity_head) {
        identity_node = list_entry(identity_list, _identity_node_t, list);
        if (identity_node->identity == information->identity) {
            list_for_each_safe(slot_list, n_b, &identity_node->slot_head) {
                slot_node = list_entry(slot_list, _slot_node_t, list);
                slot = slot_node->slot_unite;
                list_del(&slot_node->list);
                kfree(slot_node);
                delete_identity_node(information);
                
                list_for_each_safe(slot_list, n_c, &information->algorithm_head) {
                    slot_node = list_entry(slot_list, _slot_node_t, list);
                    if (slot_node->slot_unite == slot) {
                        list_del(&slot_node->list);
                        kfree(slot_node);
                    }
                }
                return slot;
            }
        }
    }
    return -1;
}

static int insert_slot_node(information_t information)
{
    int slot = 10;
    struct list_head *slot_list, *n;
    struct list_head *algorithm_head = &information->algorithm_head;
    slot_node_t slot_node = NULL;
    slot_node_t node = search_slot(information);

    if (node != NULL) {
        return node->slot_unite;
    } else {
        list_for_each_safe(slot_list, n, algorithm_head) {
            node = list_entry(slot_list, _slot_node_t, list);
            if (node->slot_unite != slot) {
                slot_node = create_slot_node(information->slot_source, information->slot_original, slot);
                list_add_tail(&slot_node->list, &node->list);
                information->slot_unite = slot;
                insert_node_in_root(information);
                return slot;
            } else 
                slot++;
        }
    }

    information->slot_unite = slot;
    slot_node = create_slot_node(information->slot_source, information->slot_original, slot);
    list_add_tail(&slot_node->list, algorithm_head);
    insert_node_in_root(information);
    return slot;
}

int virtual_touch_empty(void)
{
    int ret;
    ret = list_empty_careful(&hub_information->algorithm_head);
    if (ret && !hub_information->tp_status)
        return true;
    return false;
}
EXPORT_SYMBOL(virtual_touch_empty);

int touch_screen_set_status(int status)
{
    //status down 1 up 0
    hub_information->tp_status = status;
    return status;
}
EXPORT_SYMBOL(touch_screen_set_status);

int virtual_touch_create(void)
{
    hub_information = (information_t)kzalloc(sizeof(_information_t), GFP_KERNEL);
    INIT_LIST_HEAD(&hub_information->identity_head);
    INIT_LIST_HEAD(&hub_information->algorithm_head);
    return 0;
}
EXPORT_SYMBOL(virtual_touch_create);

//If the fd is released, you have to actively lift the unlifted contacts under the fd
int relsease_identity(void *identity)
{
    hub_information->identity = (void *)identity;

    return delete_identity_list(hub_information);
}
EXPORT_SYMBOL(relsease_identity);

/**
*   function name : 
*               slot_conver_mechanism
*   parameters : 
*               identity : Is used to distinguish identity
*               slot     : Unconverted slot
*               state    : Finger up(0) or down(1)
*   return : 
*               converted slot
*   discribe : 
*               Slot conversion mechanism
*               Provides physical and virtual touch screen merge slots
*/
int slot_conver_mechanism(void *identity, int slot, int state, int source)
{
    hub_information->identity = (void *)identity;
    hub_information->slot_original = slot;
    hub_information->slot_source = source;
    hub_information->slot_unite = insert_slot_node(hub_information);

    //If state is equal to 0, it is a up event
    if (!state) {
        delete_slot_node(hub_information);
        delete_identity_node(hub_information);

    }

    return hub_information->slot_unite;
}
EXPORT_SYMBOL(slot_conver_mechanism);
