#ifndef _NET_TRUSTCORE_INTERNAL_H
#define _NET_TRUSTCORE_INTERNAL_H

#include <linux/types.h>
#include <linux/trustcore_net.h>

struct iov_iter;

typedef void (*tc_net_inbound_fn)(const struct tc_net_desc *desc,
				  void *data,
				  u32 data_len,
				  void *aux,
				  u32 aux_len);

int trustcore_net_register_inbound_handler(tc_net_inbound_fn handler);
bool trustcore_net_ready(void);
u32 trustcore_net_max_payload(void);
bool trustcore_net_tx_ready(u32 needed);
int trustcore_net_send_desc(struct tc_net_desc *desc,
			    const void *data,
			    u32 data_len,
			    const void *aux,
			    u32 aux_len,
			    bool nonblock);
int trustcore_net_send_desc_iter(struct tc_net_desc *desc,
				 struct iov_iter *iter,
				 u32 data_len,
				 const void *aux,
				 u32 aux_len,
				 bool nonblock);
int trustcore_sock_deliver_recv(u64 stream_id, const void *data, u32 len);
int trustcore_sock_deliver_recv_from(u64 stream_id, const void *data, u32 len,
				     const void *addr, u32 addr_len);
void trustcore_sock_abort_all(int err);
int trustcore_net_cgroup_add(int fd, u64 *out_id);
int trustcore_net_cgroup_del(u64 cgroup_id);
void trustcore_net_cgroup_clear(void);

#endif /* _NET_TRUSTCORE_INTERNAL_H */
