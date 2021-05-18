#include "doca_dpdk_offload.h"
#include "doca_debug_dpdk.h"
#include "doca_log.h"
#include "rte_flow.h"
#include "rte_flow_v2.h"

DOCA_LOG_MODULE(doca_dpdk_offload);

#define HW_STEERING_MAX_QUEUES (128)
#define HW_STEERING_DESC (512)
#define HW_STEERING_MAX_PORTS (8)

struct dpdk_post_pool_queue {
    uint16_t n_desc;
    uint64_t h_desc;
    uint64_t t_desc;
    uint64_t req_id;
    uint64_t desc[0];
};

struct dpdk_post_poll_h {
    int total_queues;
    struct dpdk_post_pool_queue *desc_queues[HW_STEERING_MAX_QUEUES];
};

struct dpdk_post_poll_port {
    int num_ports;
    struct dpdk_post_poll_h ports[HW_STEERING_MAX_PORTS];
};

static struct dpdk_post_poll_port dpdk_pph;

int doca_dpdk_off_init(struct doca_flow_cfg *cfg)
{
    int i,j;
    int total_size;
    memset(&dpdk_pph, 0, sizeof(dpdk_pph));
    if (cfg->queues > HW_STEERING_MAX_QUEUES) {
        DOCA_LOG_ERR("number of queues %d exceeds max queues %d", 
                cfg->queues, HW_STEERING_MAX_QUEUES);
        return -1;
    }

    dpdk_pph.num_ports = HW_STEERING_MAX_PORTS;
    total_size = sizeof(struct dpdk_post_pool_queue)
                 + sizeof(uint64_t)*HW_STEERING_DESC; 
    for (j=0 ; j<HW_STEERING_MAX_PORTS ;j++) {
        for (i=0; i<cfg->queues; i++) {
            dpdk_pph.ports[j].desc_queues[i] = malloc(total_size);
            memset(dpdk_pph.ports[j].desc_queues[i], 0, total_size);
            dpdk_pph.ports[j].desc_queues[i]->n_desc = HW_STEERING_DESC;
            dpdk_pph.ports[j].desc_queues[i]->req_id = 1;
        }
    }
    return 0;
}

enum offload_mode {
    SW_STEERING = 1 << 0,
    HW_STEERING = 1 << 1,
};


static enum offload_mode off_mode = SW_STEERING;

static struct rte_flow *
doca_dpdk_create_flow(uint16_t port_id, const struct rte_flow_attr *attr,
		      const struct rte_flow_item pattern[],
		      const struct rte_flow_action actions[],struct doca_flow_error *derr)
{
	struct rte_flow *flow;
	struct rte_flow_error err;

	doca_dump_rte_flow("create rte flow:", port_id, attr, pattern, actions);
	flow = rte_flow_create(port_id, attr, pattern, actions, &err);
	if (!flow) {
		DOCA_LOG_ERR("Port %u create flow fail, type %d message: %s\n",
			     port_id, err.type,
			     err.message ? err.message : "(no stated reason)");
                if (derr) {
                    derr->message = err.message;
                    derr->type = DOCA_ERROR_OFFLOAD;
                }
	}
	return flow;
}


struct rte_flow_template *
doca_dpdk_pipe_create(struct doca_flow_pipe *pipe,
                        __rte_unused struct doca_flow_error *derr)
{
    struct rte_flow_error err;
    if (off_mode == SW_STEERING) {
        /* SW steering don't support template */
        return NULL;
    }

    if (off_mode == HW_STEERING) {
        struct rte_flow_template_attr attr;
        attr.flow_attr = pipe->flow.attr;
        attr.num_instances = 1000000; /* TODO: pass it */
        struct rte_flow_template *rte_ftemp = 
            rte_flow_template_create(pipe->flow.port_id,&attr, pipe->flow.items,
                                    pipe->flow.actions, &err);

        if (!rte_ftemp) {
            DOCA_LOG_ERR("Port %u create flow template fail, type %d message: %s\n",
			     pipe->flow.port_id, err.type,
			     err.message ? err.message : "(no stated reason)");
            return NULL;
        }
        pipe->flow.ftemp = rte_ftemp;
        return rte_ftemp;
    }

    return NULL;
}

static inline void 
doca_dpdk_post_save(uint16_t port_id, uint16_t pipe_queue, uint64_t req_id)
{
    struct dpdk_post_pool_queue *queue = 
            dpdk_pph.ports[port_id].desc_queues[pipe_queue];

    queue->desc[queue->t_desc % queue->n_desc] = req_id; /* we might put here rte_flow */
    queue->t_desc++;
}

/**
 * @brief - run over all out standing calls to release queue.
 *  stop when there is no more out standing req_id, or when queue
 *  is not ready.
 *
 * @param port_id
 * @param pipe_queue
 * @param req_id
 *
 * @return 
 */
static int
doca_dpdk_poll(uint16_t port_id, uint16_t pipe_queue, uint64_t *req_id)
{
#define PORT_BULK_READ (32)
    struct rte_flow_error err = {0};
    struct dpdk_post_pool_queue *queue;
    int mpoll = PORT_BULK_READ;
    uint64_t resp = 0;

    if (port_id >= dpdk_pph.num_ports) {
        DOCA_LOG_WARN("port_id %d is out of range",port_id);
        return -1;
    }
    queue = dpdk_pph.ports[port_id].desc_queues[pipe_queue];

    /* the id of the message is the tail, where desc shoulda*/
    /* be put */
    if (queue->t_desc - queue->h_desc < queue->n_desc)
        *req_id = queue->t_desc;

    /* while still has messages in the air, and has read budget */
    while (queue->t_desc - queue->h_desc > 0 && mpoll-- > 0) {
        int ret = rte_flow_q_poll(port_id, pipe_queue,
                    &resp,
                    &err);

        switch (ret) {
            case RTE_FLOW_COMPLETION_OK:
                 /* messages might not be in order,
                    but it can be ignored */
                 while (resp > queue->h_desc)
                         queue->h_desc++;
                 continue;
            case RTE_FLOW_COMPLETION_NOT_READY:
                break;
            case RTE_FLOW_COMPLETION_ERR:
                DOCA_LOG_WARN("failed on offload");
                while (resp > queue->h_desc)
                         queue->h_desc++;
                continue;
            case RTE_FLOW_COMPLETION_QP_ERR:
                DOCA_LOG_ERR("error on pool %s",err.message);
                return 0;
            default:
                DOCA_LOG_ERR("unexpected return val %d",ret);
                return -1;
        }
    }

    return 0;
}


struct rte_flow *
doca_dpdk_off_pipe_add_entry(struct doca_dpdk_pipe *pipe,uint16_t pipe_queue,
                        struct doca_flow_error *derr)
{
    if (off_mode == SW_STEERING) {
        return doca_dpdk_create_flow(pipe->port_id, &pipe->attr, pipe->items,
				     pipe->actions, derr);

    }

    if (off_mode == HW_STEERING) {
        struct rte_flow_error err = {0};
        uint64_t req_id = 0;
        struct rte_flow *rte_flow;
        if (!pipe->ftemp) {
            DOCA_LOG_ERR("HW steering add entry with no template %p",pipe->ftemp);
            return NULL;
        }

        // TODO; maybe add timeout
        doca_dpdk_poll(pipe->port_id, pipe_queue, &req_id);
        if (req_id == 0) {
            DOCA_LOG_ERR("no desc");
            return NULL;
        }

        rte_flow =
            rte_flow_q_post_flow_create(pipe->port_id,
			    pipe_queue,  /*uint16_t fq_id,*/
			    0, /* flags */
			    req_id, /* uint64_t req_id,*/
			    pipe->ftemp,
			    pipe->items, /* --> WHY type&mask are NULL */
			    pipe->actions, /* >=template */
			    &err);

        if (!rte_flow) {
		DOCA_LOG_ERR("Port %u create flow fail, type %d message: %s\n",
			     pipe->port_id, err.type,
			     err.message ? err.message : "(no stated reason)");
                if (derr) {
                    derr->message = err.message;
                    derr->type = DOCA_ERROR_OFFLOAD;
                }
	}
        doca_dpdk_post_save(pipe->port_id, pipe_queue, req_id);
        return rte_flow;
    }

    return NULL;
}


