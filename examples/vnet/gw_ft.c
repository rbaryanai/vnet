#include <unistd.h>
#include <stdio.h>
#include "rte_mbuf.h"
#include "gw_ft.h"
#include "rte_hash_crc.h"
#include "rte_malloc.h"
#include "rte_ip.h"
#include "rte_tcp.h"
#include "rte_udp.h"
#include "rte_spinlock.h"

#include "doca_log.h"

DOCA_LOG_MODULE(flow_table)

struct gw_ft_entry {
    LIST_ENTRY(gw_ft_entry) next; /* entry pointers in the list. */
    struct gw_ft_key key;
    uint64_t expiration;
    uint64_t last_counter;
    uint64_t sw_ctr;
    uint8_t hw_off;

    struct gw_ft_user_ctx user_ctx;
};

LIST_HEAD(gw_ft_entry_head, gw_ft_entry );

struct gw_ft_bucket {
    struct gw_ft_entry_head head;
    rte_spinlock_t lock;
};


struct gw_ft_stats {
    uint64_t add;
    uint64_t rm;

    uint64_t memuse;
};

struct gw_ft_cfg {
    uint32_t size;
    uint32_t mask;
    uint32_t user_data_size;
    uint32_t entry_size;
};

struct gw_ft {
    struct gw_ft_cfg cfg;
    struct gw_ft_stats stats;
    volatile int stop_aging_thread;
    uint32_t fid_ctr;
    rte_spinlock_t lock;

    struct gw_ft_bucket buckets[0];
};


static void * gw_ft_aging_main(void *void_ptr)
{
    unsigned int i;
    struct gw_ft * ft = (struct gw_ft *) void_ptr; 
    struct gw_ft_entry_head *first;
    struct gw_ft_entry *node;
    if (!ft){
        //DOCA_LOG_ERR("no ft, abort aging\n");
        return NULL;
    }

    while(!ft->stop_aging_thread){
        uint64_t t = rte_rdtsc();

        DOCA_LOG_INFO("total entries: %d\n", (int) (ft->stats.add - ft->stats.rm));

        if( rte_spinlock_trylock(&ft->lock) ) {
            for(i = 0 ; i < ft->cfg.size ; i++){
                first = &ft->buckets[i].head;
                LIST_FOREACH(node, first, next) {
                    if(node->hw_off) {
                        /* TODO: support in HW */
                    }
                    if(node->expiration < t){
                        DOCA_LOG_INFO("removing flow\n");
                        gw_ft_destory_flow(ft, &node->key);
                        break;
                    }
                }
            }
            rte_spinlock_unlock(&ft->lock);
        }
        sleep(1);
    }

    return NULL;

}

/**
 * @brief - start per flow table aging thread
 *
 * @param ft
 */
static void gw_ft_aging_thread_start(struct gw_ft *ft)
{
    pthread_t inc_x_thread;

    // create a second thread which executes inc_x(&x) 
    if(pthread_create(&inc_x_thread, NULL, gw_ft_aging_main, ft)) {
        fprintf(stderr, "Error creating thread\n");
    }
}

static uint32_t gw_ft_key_hash(struct gw_ft_key *key)
{
    uint32_t hash = 0;
    if(!key){
        return 0;
    }
    hash = rte_hash_crc_4byte(key->ipv4_1, hash);
    hash = rte_hash_crc_2byte(key->port_1, hash);
    hash = rte_hash_crc_4byte(key->ipv4_2, hash);
    hash = rte_hash_crc_2byte(key->port_2, hash);
    hash = rte_hash_crc_1byte(key->protocol, hash);

    return hash;
}

struct gw_ft *gw_ft_create(int size, uint32_t user_data_size)
{
    struct gw_ft *ft;
    uint32_t act_size;
    uint32_t alloc_size;

    if (!size)
            return NULL;
    /* Align to the next power of 2, 32bits integer is enough now. */
    if (!rte_is_power_of_2(size)) {
            act_size = rte_align32pow2(size);
    } else {
            act_size = size;
    }
    alloc_size = sizeof(struct gw_ft) +
		     sizeof(struct  gw_ft_bucket) * act_size;
   DOCA_LOG_DBG("alloc size =%d\n",alloc_size);

    ft = malloc(alloc_size*2);
    memset(ft, 0 , alloc_size);
    if (ft == NULL) {
        printf("error: not mem\n");
        return NULL;
    }

    ft->cfg.entry_size = sizeof(struct gw_ft_entry) + user_data_size;
    ft->cfg.user_data_size = user_data_size;
    ft->cfg.size = act_size;
    ft->cfg.mask = act_size - 1;
        
    DOCA_LOG_DBG("FT create size=%d, user_data_size=%d\n",size, user_data_size);

    rte_spinlock_init(&ft->lock);
    gw_ft_aging_thread_start(ft);
    return ft;
}




static
struct gw_ft_entry *_gw_ft_find(struct gw_ft *ft, struct gw_ft_key *key)
{
    uint32_t hash;
    uint32_t idx;
    struct gw_ft_entry_head *first;
    struct gw_ft_entry *node;

    hash = gw_ft_key_hash(key);
    idx = hash & ft->cfg.mask;
    DOCA_LOG_DBG("looking for index%d\n",idx);
    first = &ft->buckets[idx].head;
    LIST_FOREACH(node, first, next) {
        if (gw_ft_key_equal(&node->key, key)){
            return node;
        }
    }
    return NULL;
}

bool gw_ft_find(struct gw_ft *ft, struct gw_pkt_info *pinfo, 
                                 struct gw_ft_user_ctx **ctx)
{
    struct gw_ft_entry *fe;
    struct gw_ft_key key = {0};
    if (gw_ft_key_fill(pinfo, &key))
        return false;

    fe = _gw_ft_find(ft, &key);
    if (fe == NULL )
        return false;

    *ctx = &fe->user_ctx;    
    return true; 
}

bool gw_ft_add_new(struct gw_ft *ft, struct gw_pkt_info *pinfo,struct gw_ft_user_ctx **ctx)
{
    uint32_t hash;
    int idx;
    struct gw_ft_key key = {0};
    struct gw_ft_entry *new_e;
    struct gw_ft_entry_head *first;
    uint64_t sec = rte_get_timer_hz();
    uint64_t t  =  rte_rdtsc();

    if(!ft){
        return false;
    }

    if (gw_ft_key_fill(pinfo, &key)){
        fprintf(stderr,"failed on key\n");
       return false;
    }

    new_e = malloc(ft->cfg.entry_size);
    if (new_e == NULL) {
        printf("error:oom\n");
        return false;
    }

    memset(new_e,0,ft->cfg.entry_size);
    new_e->expiration = t + sec*10;
    new_e->user_ctx.fid = ft->fid_ctr++;

    DOCA_LOG_DBG("defined new flow %llu\n", (unsigned int long long)new_e->user_ctx.fid);
    memcpy(&new_e->key, &key, sizeof(struct gw_ft_key));
    hash = gw_ft_key_hash(&key);
    idx = hash & ft->cfg.mask;
    first = &ft->buckets[idx].head;

    rte_spinlock_lock(&ft->lock);
    LIST_INSERT_HEAD(first, new_e, next);
    DOCA_LOG_DBG("added on index %d\n",idx);
    *ctx = &new_e->user_ctx;
    ft->stats.add++;
    rte_spinlock_unlock(&ft->lock);
    return true;
}

int
gw_ft_destory_flow(struct gw_ft *ft, struct gw_ft_key *key)
{
    struct gw_ft_entry *f;
    if(!key || !ft){
        return -1;
    }

    f = _gw_ft_find(ft, key);

    if(f){
	LIST_REMOVE(f, next);
        free(f);
        ft->stats.rm++;
    }
    return 0;
}


void gw_ft_destroy(struct gw_ft *ft)
{
    uint32_t i; 
    struct gw_ft_entry_head *first;
    struct gw_ft_entry *node;

    ft->stop_aging_thread = true;
    rte_spinlock_lock(&ft->lock);
    for (i = 0 ; i < ft->cfg.size ; i++) {
        do {
            first = &ft->buckets[i].head;
            LIST_FOREACH(node, first, next) {
                LIST_REMOVE(node, next);
                free(node);
                continue; 
            }
        } while (0);
    }
    rte_spinlock_unlock(&ft->lock);
    free(ft);
}
