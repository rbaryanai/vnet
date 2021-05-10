#include "rte_hash.h"
#include "rte_hash_crc.h"
#include "doca_encap_table.h"
#include "doca_log.h"
#include "rte_spinlock.h"

DOCA_LOG_MODULE(doca_encap_table);

#define ENCAP_HASH_ENTRIES 1024

struct encap_table_key {
        struct doca_ip_addr src_ip;
	struct doca_ip_addr dst_ip;
	struct doca_flow_tun tun;
};

struct encap_table_entry {
    uint8_t *data;
    bool     used;
    uint32_t refcnt;
    struct encap_table_key key;
};

struct encap_table {
    int max;
    int size;
    rte_spinlock_t lock;
    struct rte_hash *h;
    struct encap_table_entry entries[0];
};

static struct encap_table *encap_table_ins;

static inline uint32_t
encap_hash_crc(const void *data, __rte_unused uint32_t data_len,
        uint32_t init_val)
{
    const struct encap_table_key *k;
    k = data;
    init_val = rte_hash_crc_4byte(k->src_ip.a.ipv4_addr, init_val);
    init_val = rte_hash_crc_4byte(k->dst_ip.a.ipv4_addr, init_val);
    switch (k->tun.type) {
        case DOCA_TUN_VXLAN:
            init_val = rte_hash_crc_4byte(k->tun.vxlan.tun_id, init_val);
            break;
	case DOCA_TUN_GRE:
            init_val = rte_hash_crc_4byte(k->tun.gre.key, init_val);
            break;
        default:
            break;
    }
    return init_val;
}
struct rte_hash_parameters encap_table_hash_params = {
        .name = NULL,
        .entries = ENCAP_HASH_ENTRIES,
        .key_len = sizeof(struct encap_table_key),
        .hash_func = encap_hash_crc,
        .hash_func_init_val = 0,
};

int doca_encap_table_init(int max_encaps)
{
    int total_size = sizeof(struct encap_table) +
                     sizeof(struct encap_table_entry)*max_encaps;
    encap_table_ins = (struct encap_table *) malloc(total_size);
    if (encap_table_ins == NULL) {
        DOCA_LOG_ERR("failed to alloc mem");
        return -1;
    }

    /* TBD: for now using dpdk hash, might need a change 
     * if should be accessed a lot from multi cores */
    memset(encap_table_ins, 0, sizeof(total_size));
    encap_table_hash_params.entries = max_encaps;
    encap_table_ins->h = rte_hash_create(&encap_table_hash_params);
    encap_table_ins->max = max_encaps;

    if (encap_table_ins->h == NULL) {
        DOCA_LOG_ERR("failed to alloc hash table");
        return -1;
    }
    rte_spinlock_init(&encap_table_ins->lock);

    DOCA_LOG_INFO("table created");
    return 0;
}

int doca_encap_table_add_id(struct doca_flow_encap_action *ea)
{
    struct encap_table_key key = {0};
    int id = 0;
    if ((id = doca_encap_table_get_id(ea)) >= 0) 
        return id;

    if (encap_table_ins->size >= encap_table_ins->max) {
        DOCA_LOG_WARN("max size reached");
        return -1;
    }

    if (key.src_ip.type != 4) {
        DOCA_LOG_WARN("support only ipv4");
        return -1;
    }

    key.src_ip = ea->src_ip;
    key.dst_ip = ea->dst_ip;
    key.tun = ea->tun;
    rte_spinlock_lock(&encap_table_ins->lock);
    id = rte_hash_add_key(encap_table_ins->h, (void *) &key);
    encap_table_ins->entries[id].used = true;
    encap_table_ins->entries[id].data = NULL;
    encap_table_ins->entries[id].key = key;
    encap_table_ins->entries[id].refcnt = 1;
    rte_spinlock_unlock(&encap_table_ins->lock);
    return id;
}

int doca_encap_table_get_id(struct doca_flow_encap_action *ea)
{
    int id;
    struct encap_table_key key = {0};

    key.src_ip = ea->src_ip;
    key.dst_ip = ea->dst_ip;
    key.tun = ea->tun;

    rte_spinlock_lock(&encap_table_ins->lock);
    id = rte_hash_lookup(encap_table_ins->h, (void *) &key);
    rte_spinlock_unlock(&encap_table_ins->lock);
    return id;
}

int doca_encap_table_udpate_data(int id, uint8_t *data)
{
    if (id < 0 || id > encap_table_ins->max) 
        return -1;
    
    rte_spinlock_lock(&encap_table_ins->lock);
    if (encap_table_ins->entries[id].used) {
        encap_table_ins->entries[id].data = data;
        rte_spinlock_unlock(&encap_table_ins->lock);
        return 0;
    }
    rte_spinlock_unlock(&encap_table_ins->lock);
    return -1;
}

int doca_encap_table_remove_id(int id)
{
     if (id < 0 || id > encap_table_ins->max) 
        return  0;

    rte_spinlock_lock(&encap_table_ins->lock);
    if (encap_table_ins->entries[id].used) {
        if (--encap_table_ins->entries[id].refcnt){
            int refcnt = encap_table_ins->entries[id].refcnt;
            rte_spinlock_unlock(&encap_table_ins->lock);
            return refcnt;
        }

        rte_hash_del_key(encap_table_ins->h, &encap_table_ins->entries[id].key);
        memset(&encap_table_ins->entries[id],0,
                    sizeof(struct encap_table_entry));
    }
    rte_spinlock_unlock(&encap_table_ins->lock);
    return 0;
}

/**
 * @brief - if ea exits
 *
 * @param ea
 *
 * @return 
 */
uint8_t *doca_encap_table_get_data(struct doca_flow_encap_action *ea)
{
    int id = doca_encap_table_get_id(ea);
    if (id >= 0) {
        uint8_t *data = NULL;
        rte_spinlock_lock(&encap_table_ins->lock);
        if (encap_table_ins->entries[id].used) {
            data = encap_table_ins->entries[id].data;
        }
        rte_spinlock_unlock(&encap_table_ins->lock);
        return data;
    }
    return NULL;
}



