#ifndef RTE_FLOW_V2_H
#define RTE_FLOW_V2_H

#include <stdint.h>
#include <stdbool.h>
#include "rte_flow.h"
int
rte_flow_group_create(uint16_t port_id,
		      const struct rte_flow_attr *attr,
		      struct rte_flow_error *error);

int
rte_flow_group_destroy(uint16_t port_id,
		       const struct rte_flow_attr *attr,
		       struct rte_flow_error *error);

struct rte_flow_template_attr {
	struct rte_flow_attr flow_attr;
	size_t num_instances; /* no guaranty */
};

struct rte_flow_template *
rte_flow_template_create(uint16_t port_id,
			 const struct rte_flow_template_attr *attr,
			 const struct rte_flow_item pattern[], /* spec=NULL */
						      /* TODO: last? range? */
			 const struct rte_flow_action actions[], /* conf=NULL|set */
			 struct rte_flow_error *error);

int
rte_flow_template_destroy(uint16_t port_id,
			  struct rte_flow_template *flow_template,
			  struct rte_flow_error *error);

enum {
	RTE_FLOW_Q_FLAG_MORE_REQ	= (1 << 0),
};

struct rte_flow *
rte_flow_q_post_flow_create(uint16_t port_id,
			    uint16_t fq_id,
			    uint8_t fq_flags,
			    uint64_t req_id,
			    struct rte_flow_template *flow_template,
			    const struct rte_flow_item pattern[], /* type&mask are NULL */
			    const struct rte_flow_action actions[], /* >=template */
			    struct rte_flow_error *error);

int
rte_flow_q_post_flow_destroy(uint16_t port_id,
			     uint16_t fq_id,
			     uint8_t fq_flags,
			     uint64_t req_id,
			     struct rte_flow *flow,
			     struct rte_flow_error *error);

// TODO: fq post shared action create/modify/query/destroy

enum {
         RTE_FLOW_COMPLETION_OK,
         RTE_FLOW_COMPLETION_NOT_READY,
         RTE_FLOW_COMPLETION_ERR,
         RTE_FLOW_COMPLETION_QP_ERR,
};

int
rte_flow_q_poll(uint16_t port_id,
		uint16_t fq_id,
		uint64_t *req_id,
		struct rte_flow_error *error);

// TODO: core direct

#endif
