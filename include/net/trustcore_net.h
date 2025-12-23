#ifndef _NET_TRUSTCORE_NET_H
#define _NET_TRUSTCORE_NET_H

#include <linux/types.h>

struct proto;
struct proto_ops;

#ifdef CONFIG_TRUSTCORE_NET
extern struct proto trustcore_proto;
extern const struct proto_ops trustcore_inet_ops;
extern const struct proto_ops trustcore_inet6_ops;

bool trustcore_net_should_intercept(int sock_type, int protocol);
bool trustcore_net_ready(void);
#else
static inline bool trustcore_net_should_intercept(int sock_type, int protocol)
{
	return false;
}

static inline bool trustcore_net_ready(void)
{
	return false;
}
#endif

#endif /* _NET_TRUSTCORE_NET_H */
