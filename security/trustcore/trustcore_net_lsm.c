// SPDX-License-Identifier: GPL-2.0
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/net.h>
#include <linux/socket.h>

static int trustcore_net_socket_create(int family, int type, int protocol, int kern)
{
	if (kern)
		return 0;

	if (family == AF_UNIX || family == AF_VSOCK)
		return 0;

	if (family == AF_INET || family == AF_INET6) {
		int sock_type = type & SOCK_TYPE_MASK;

		if (sock_type == SOCK_STREAM) {
			if (protocol == 0 || protocol == IPPROTO_TCP)
				return 0;
			return -EPERM;
		}
		if (sock_type == SOCK_DGRAM) {
			if (protocol == 0 || protocol == IPPROTO_UDP)
				return 0;
			return -EPERM;
		}
		return -EPERM;
	}

	return -EPERM;
}

static struct security_hook_list trustcore_net_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(socket_create, trustcore_net_socket_create),
};

static struct lsm_id trustcore_net_lsmid __lsm_ro_after_init = {
	.name = "trustcore_net",
};

static int __init trustcore_net_lsm_init(void)
{
	security_add_hooks(trustcore_net_hooks, ARRAY_SIZE(trustcore_net_hooks),
			   &trustcore_net_lsmid);
	return 0;
}

DEFINE_LSM(trustcore_net) = {
	.name = "trustcore_net",
	.init = trustcore_net_lsm_init,
	.order = LSM_ORDER_LAST,
};
