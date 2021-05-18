#include "rte_flow_v2.h"

struct rte_flow_template {
    int n;
};

int
rte_flow_group_create(__rte_unused uint16_t port_id,
		      __rte_unused const struct rte_flow_attr *attr,
		      __rte_unused struct rte_flow_error *error)
{
    return 0;
}

int
rte_flow_group_destroy(__rte_unused uint16_t port_id,
		       __rte_unused const struct rte_flow_attr *attr,
		       __rte_unused struct rte_flow_error *error)
{
    return 0;
}

static struct rte_flow_template temp = {0};

struct rte_flow_template *
rte_flow_template_create(__rte_unused uint16_t port_id,
			 __rte_unused const struct rte_flow_template_attr *attr,
			 __rte_unused const struct rte_flow_item pattern[], /* spec=NULL */
						      /* TODO: last? range? */
			 __rte_unused const struct rte_flow_action actions[], /* conf=NULL|set */
			 __rte_unused struct rte_flow_error *error)
{
    return &temp;
}

int
rte_flow_template_destroy(__rte_unused uint16_t port_id,
			  __rte_unused struct rte_flow_template *flow_template,
			  __rte_unused struct rte_flow_error *error)
{
    return 0;
}

/*enum {
	RTE_FLOW_Q_FLAG_MORE_REQ	= (1 << 0),
};*/


static int dummy = 0;

struct rte_flow *
rte_flow_q_post_flow_create(__rte_unused uint16_t port_id,
			    __rte_unused uint16_t fq_id,
			    __rte_unused uint8_t fq_flags,
			    __rte_unused uint64_t req_id,
			    __rte_unused struct rte_flow_template *flow_template,
			    __rte_unused const struct rte_flow_item pattern[], /* type&mask are NULL */
			    __rte_unused const struct rte_flow_action actions[], /* >=template */
			    __rte_unused struct rte_flow_error *error)
{
    printf("ok reqid = %llu\n",(unsigned long long int) req_id);
    return (struct rte_flow *) &dummy;
}

int
rte_flow_q_post_flow_destroy(__rte_unused uint16_t port_id,
			     __rte_unused uint16_t fq_id,
			     __rte_unused uint8_t fq_flags,
			     __rte_unused uint64_t req_id,
			     __rte_unused struct rte_flow *flow,
			     __rte_unused struct rte_flow_error *error)
{
    return 0;
}

// TODO: fq post shared action create/modify/query/destroy


int
rte_flow_q_poll(__rte_unused uint16_t port_id,
		__rte_unused uint16_t fq_id,
		__rte_unused uint64_t *req_id,
		__rte_unused struct rte_flow_error *error)
{
    return RTE_FLOW_COMPLETION_OK;
}



