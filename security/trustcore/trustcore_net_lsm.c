// SPDX-License-Identifier: GPL-2.0
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/socket.h>

static void trustcore_net_log_deny(int family, int type, int protocol)
{
	uid_t uid = from_kuid_munged(current_user_ns(), current_uid());
	gid_t gid = from_kgid_munged(current_user_ns(), current_gid());

	pr_err("trustcore_net: denied socket family=%d type=%d proto=%d tgid=%u uid=%u gid=%u\n",
	       family, type, protocol, current->tgid, uid, gid);
	dump_stack();
}

static int trustcore_net_socket_create(int family, int type, int protocol, int kern)
{
	if (kern)
		return 0;

	if (family == AF_UNIX || family == AF_VSOCK)
		return 0;

	if (family == AF_NETLINK) {
		int sock_type = type & SOCK_TYPE_MASK;

		if (sock_type == SOCK_RAW || sock_type == SOCK_DGRAM) {
			if (protocol == NETLINK_ROUTE || protocol == NETLINK_GENERIC)
				return 0;
		}
		trustcore_net_log_deny(family, type, protocol);
		return -EPERM;
	}

	if (family == AF_INET || family == AF_INET6) {
		int sock_type = type & SOCK_TYPE_MASK;

		if (sock_type == SOCK_STREAM) {
			if (protocol == 0 || protocol == IPPROTO_TCP)
				return 0;
			trustcore_net_log_deny(family, type, protocol);
			return -EPERM;
		}
		if (sock_type == SOCK_DGRAM) {
			if (protocol == 0 || protocol == IPPROTO_UDP)
				return 0;
			trustcore_net_log_deny(family, type, protocol);
			return -EPERM;
		}
		trustcore_net_log_deny(family, type, protocol);
		return -EPERM;
	}

	trustcore_net_log_deny(family, type, protocol);
	return -EPERM;
}

static struct security_hook_list trustcore_net_hooks[] = {
	LSM_HOOK_INIT(socket_create, trustcore_net_socket_create),
};

static struct lsm_id trustcore_net_lsmid = {
	.name = "trustcore_net",
	.id = LSM_ID_UNDEF,
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
