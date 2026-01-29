#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/poll.h>
#include <linux/cred.h>
#include <linux/debugfs.h>
#include <linux/ipv6.h>
#include <linux/mm.h>
#include <linux/limits.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/uio.h>
#include <linux/cgroup.h>
#include <linux/seq_file.h>
#include <net/inet_common.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <net/tcp_states.h>

#include "trustcore_internal.h"
#include <net/trustcore_net.h>

#define TRUSTCORE_TX_READY_MIN 1u
#define TRUSTCORE_RX_MAX_BYTES (4u * 1024u * 1024u)
#define TRUSTCORE_RX_MAX_BUFS 1024u
#define TRUSTCORE_INTERCEPT_OFF 0
#define TRUSTCORE_INTERCEPT_ON 1
#define TRUSTCORE_INTERCEPT_UID 2
#define TRUSTCORE_INTERCEPT_GID 3
#define TRUSTCORE_INTERCEPT_CGROUP 4

struct tc_rx_buf {
	struct list_head list;
	size_t offset;
	size_t len;
	u32 addr_len;
	struct sockaddr_storage addr;
	u8 data[];
};

struct tc_accept_entry {
	struct list_head list;
	struct list_head rx_queue;
	u32 rx_queued_bytes;
	u32 rx_queued_bufs;
	u64 stream_id;
	struct sockaddr_storage peer;
	int peer_len;
	struct hlist_node node;
};

struct tc_sock {
	struct inet_sock inet;
#if IS_ENABLED(CONFIG_IPV6)
	struct ipv6_pinfo inet6;
#endif
	u64 stream_id;
	u64 listener_id;
	u64 pending_req_id;
	int pending_status;
	bool closing;
	bool listening;
	bool dgram_connected;
	bool dgram_host_ready;
	struct sockaddr_storage peer;
	int peer_len;
	struct sockaddr_storage local;
	int local_len;
	wait_queue_head_t wait;
	spinlock_t rx_lock;
	struct list_head rx_queue;
	u32 rx_queued_bytes;
	u32 rx_queued_bufs;
	spinlock_t accept_lock;
	struct list_head accept_queue;
	struct hlist_node stream_node;
	struct hlist_node listener_node;
	struct hlist_node req_node;
};

static DEFINE_HASHTABLE(tc_streams, 10);
static DEFINE_HASHTABLE(tc_listeners, 10);
static DEFINE_HASHTABLE(tc_requests, 10);
static DEFINE_HASHTABLE(tc_pending_accepts, 10);
static DEFINE_SPINLOCK(tc_streams_lock);
static DEFINE_SPINLOCK(tc_listeners_lock);
static DEFINE_SPINLOCK(tc_requests_lock);
static DEFINE_SPINLOCK(tc_pending_accepts_lock);

static atomic64_t tc_next_stream_id = ATOMIC64_INIT(1);
static atomic64_t tc_next_listener_id = ATOMIC64_INIT(1);
static atomic64_t tc_next_req_id = ATOMIC64_INIT(1);
static atomic64_t tc_rx_dropped = ATOMIC64_INIT(0);
static atomic64_t tc_rx_oom = ATOMIC64_INIT(0);
static int trustcore_intercept_mode = TRUSTCORE_INTERCEPT_ON;
static int trustcore_intercept_uid = -1;
static int trustcore_intercept_gid = -1;

module_param(trustcore_intercept_mode, int, 0644);
MODULE_PARM_DESC(trustcore_intercept_mode, "0=off 1=on 2=uid 3=gid 4=cgroup");
module_param(trustcore_intercept_uid, int, 0644);
MODULE_PARM_DESC(trustcore_intercept_uid, "Intercept only for matching UID (mode=2)");
module_param(trustcore_intercept_gid, int, 0644);
MODULE_PARM_DESC(trustcore_intercept_gid, "Intercept only for matching GID (mode=3)");

int trustcore_net_set_intercept(const struct tc_net_intercept_req *req)
{
	if (!req)
		return -EINVAL;

	switch (req->mode) {
	case TRUSTCORE_INTERCEPT_OFF:
	case TRUSTCORE_INTERCEPT_ON:
		WRITE_ONCE(trustcore_intercept_uid, -1);
		WRITE_ONCE(trustcore_intercept_gid, -1);
		break;
	case TRUSTCORE_INTERCEPT_UID:
		if (req->uid < 0)
			return -EINVAL;
		WRITE_ONCE(trustcore_intercept_uid, req->uid);
		WRITE_ONCE(trustcore_intercept_gid, -1);
		break;
	case TRUSTCORE_INTERCEPT_GID:
		if (req->gid < 0)
			return -EINVAL;
		WRITE_ONCE(trustcore_intercept_gid, req->gid);
		WRITE_ONCE(trustcore_intercept_uid, -1);
		break;
	case TRUSTCORE_INTERCEPT_CGROUP:
		WRITE_ONCE(trustcore_intercept_uid, -1);
		WRITE_ONCE(trustcore_intercept_gid, -1);
		break;
	default:
		return -EINVAL;
	}

	WRITE_ONCE(trustcore_intercept_mode, req->mode);
	return 0;
}
EXPORT_SYMBOL_GPL(trustcore_net_set_intercept);

void trustcore_net_get_intercept(struct tc_net_intercept_req *req)
{
	if (!req)
		return;
	req->mode = READ_ONCE(trustcore_intercept_mode);
	req->uid = READ_ONCE(trustcore_intercept_uid);
	req->gid = READ_ONCE(trustcore_intercept_gid);
	req->flags = 0;
}
EXPORT_SYMBOL_GPL(trustcore_net_get_intercept);

struct tc_cgroup_entry {
	struct list_head list;
	struct cgroup *cgrp;
	u64 id;
};

static LIST_HEAD(tc_cgroup_list);
static DEFINE_MUTEX(tc_cgroup_lock);

#ifdef CONFIG_DEBUG_FS
static struct dentry *tc_sock_debugfs_dir;

static int tc_debugfs_sock_show(struct seq_file *s, void *unused)
{
	seq_printf(s, "rx_dropped %lld\n", atomic64_read(&tc_rx_dropped));
	seq_printf(s, "rx_oom %lld\n", atomic64_read(&tc_rx_oom));
	return 0;
}

static int tc_debugfs_sock_open(struct inode *inode, struct file *file)
{
	return single_open(file, tc_debugfs_sock_show, NULL);
}

static const struct file_operations tc_debugfs_sock_fops = {
	.owner = THIS_MODULE,
	.open = tc_debugfs_sock_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

static inline struct tc_sock *tc_sk(struct sock *sk)
{
	return container_of(inet_sk(sk), struct tc_sock, inet);
}

static void tc_register_stream(struct tc_sock *tc)
{
	spin_lock(&tc_streams_lock);
	if (hlist_unhashed(&tc->stream_node))
		hash_add(tc_streams, &tc->stream_node, tc->stream_id);
	spin_unlock(&tc_streams_lock);
}

static void tc_unregister_stream(struct tc_sock *tc)
{
	spin_lock(&tc_streams_lock);
	if (!hlist_unhashed(&tc->stream_node))
		hlist_del_init(&tc->stream_node);
	spin_unlock(&tc_streams_lock);
}

static struct sock *tc_find_stream_sk(u64 stream_id)
{
	struct tc_sock *tc;
	struct sock *sk = NULL;

	spin_lock(&tc_streams_lock);
	hash_for_each_possible(tc_streams, tc, stream_node, stream_id) {
		if (tc->stream_id == stream_id) {
			sk = &tc->inet.sk;
			sock_hold(sk);
			break;
		}
	}
	spin_unlock(&tc_streams_lock);
	return sk;
}

int trustcore_sock_deliver_recv(u64 stream_id, const void *data, u32 len)
{
	return trustcore_sock_deliver_recv_from(stream_id, data, len, NULL, 0);
}

int trustcore_sock_deliver_recv_from(u64 stream_id, const void *data, u32 len,
				     const void *addr, u32 addr_len)
{
	struct sock *sk;
	struct tc_sock *tc;
	struct tc_accept_entry *entry;
	struct tc_rx_buf *buf;
	u32 new_bytes;
	bool log_pending = false;
	bool log_drop = false;
	bool log_queue = false;
	u32 log_bytes = 0;
	u32 log_bufs = 0;

	if (!data || !len)
		return 0;
	if (addr_len > sizeof(struct sockaddr_storage))
		return -EINVAL;

	sk = tc_find_stream_sk(stream_id);
	if (!sk) {
		buf = kzalloc(sizeof(*buf) + len, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		memcpy(buf->data, data, len);
		buf->len = len;
		buf->addr_len = 0;
		if (addr && addr_len) {
			memcpy(&buf->addr, addr, addr_len);
			buf->addr_len = addr_len;
		}

		spin_lock(&tc_pending_accepts_lock);
		hash_for_each_possible(tc_pending_accepts, entry, node, stream_id) {
			if (entry->stream_id == stream_id) {
				if (entry->rx_queued_bufs >= TRUSTCORE_RX_MAX_BUFS ||
				    check_add_overflow(entry->rx_queued_bytes, len, &new_bytes) ||
				    new_bytes > TRUSTCORE_RX_MAX_BYTES) {
					spin_unlock(&tc_pending_accepts_lock);
					kfree(buf);
					atomic64_inc(&tc_rx_dropped);
					return -ENOBUFS;
				}
				entry->rx_queued_bytes = new_bytes;
				entry->rx_queued_bufs += 1;
				list_add_tail(&buf->list, &entry->rx_queue);
				log_pending = true;
				log_bytes = entry->rx_queued_bytes;
				log_bufs = entry->rx_queued_bufs;
				spin_unlock(&tc_pending_accepts_lock);
				pr_info("trustcore-sock: buffered recv stream_id=%llu len=%u queued_bytes=%u queued_bufs=%u\n",
					stream_id, len, log_bytes, log_bufs);
				return 0;
			}
		}
		spin_unlock(&tc_pending_accepts_lock);
		kfree(buf);
		log_drop = true;
		if (log_drop)
			pr_info("trustcore-sock: drop recv stream_id=%llu len=%u (no stream/pending)\n",
				stream_id, len);
		return 0;
	}

	tc = tc_sk(sk);
	spin_lock(&tc->rx_lock);
	if (tc->rx_queued_bufs >= TRUSTCORE_RX_MAX_BUFS ||
	    check_add_overflow(tc->rx_queued_bytes, len, &new_bytes) ||
	    new_bytes > TRUSTCORE_RX_MAX_BYTES) {
		spin_unlock(&tc->rx_lock);
		atomic64_inc(&tc_rx_dropped);
		sock_put(sk);
		return -ENOBUFS;
	}
	tc->rx_queued_bytes = new_bytes;
	tc->rx_queued_bufs += 1;
	spin_unlock(&tc->rx_lock);

	buf = kzalloc(sizeof(*buf) + len, GFP_KERNEL);
	if (!buf) {
		spin_lock(&tc->rx_lock);
		tc->rx_queued_bytes -= len;
		tc->rx_queued_bufs -= 1;
		spin_unlock(&tc->rx_lock);
		atomic64_inc(&tc_rx_oom);
		sock_put(sk);
		return -ENOMEM;
	}
	memcpy(buf->data, data, len);
	buf->len = len;
	buf->addr_len = 0;
	if (addr && addr_len) {
		memcpy(&buf->addr, addr, addr_len);
		buf->addr_len = addr_len;
	}
	spin_lock(&tc->rx_lock);
	list_add_tail(&buf->list, &tc->rx_queue);
	log_queue = true;
	log_bytes = tc->rx_queued_bytes;
	log_bufs = tc->rx_queued_bufs;
	spin_unlock(&tc->rx_lock);
	tc->inet.sk.sk_state_change(&tc->inet.sk);
	wake_up_interruptible(&tc->wait);
	sock_put(sk);
	if (log_queue)
		pr_info("trustcore-sock: queued recv stream_id=%llu len=%u queued_bytes=%u queued_bufs=%u\n",
			stream_id, len, log_bytes, log_bufs);
	return 0;
}

static void tc_register_listener(struct tc_sock *tc)
{
	spin_lock(&tc_listeners_lock);
	hash_add(tc_listeners, &tc->listener_node, tc->listener_id);
	spin_unlock(&tc_listeners_lock);
}

static void tc_unregister_listener(struct tc_sock *tc)
{
	spin_lock(&tc_listeners_lock);
	if (!hlist_unhashed(&tc->listener_node))
		hlist_del_init(&tc->listener_node);
	spin_unlock(&tc_listeners_lock);
}

static struct sock *tc_find_listener_sk(u64 listener_id)
{
	struct tc_sock *tc;
	struct sock *sk = NULL;

	spin_lock(&tc_listeners_lock);
	hash_for_each_possible(tc_listeners, tc, listener_node, listener_id) {
		if (tc->listener_id == listener_id) {
			sk = &tc->inet.sk;
			sock_hold(sk);
			break;
		}
	}
	spin_unlock(&tc_listeners_lock);
	return sk;
}

static void tc_register_request(struct tc_sock *tc, u64 req_id)
{
	tc->pending_req_id = req_id;
	spin_lock(&tc_requests_lock);
	hash_add(tc_requests, &tc->req_node, req_id);
	spin_unlock(&tc_requests_lock);
}

static void tc_unregister_request(struct tc_sock *tc)
{
	spin_lock(&tc_requests_lock);
	if (!hlist_unhashed(&tc->req_node))
		hlist_del_init(&tc->req_node);
	spin_unlock(&tc_requests_lock);
	tc->pending_req_id = 0;
}

static struct sock *tc_find_request_sk(u64 req_id)
{
	struct tc_sock *tc;
	struct sock *sk = NULL;

	spin_lock(&tc_requests_lock);
	hash_for_each_possible(tc_requests, tc, req_node, req_id) {
		if (tc->pending_req_id == req_id) {
			sk = &tc->inet.sk;
			sock_hold(sk);
			break;
		}
	}
	spin_unlock(&tc_requests_lock);
	return sk;
}

static void tc_complete_request(struct tc_sock *tc, int status)
{
	struct sock *sk = &tc->inet.sk;

	/* status is expected to be 0 or a positive errno value */
	tc->pending_status = status;
	tc_unregister_request(tc);
	sk->sk_err = status;
	sk->sk_state_change(sk);
	wake_up_interruptible(&tc->wait);
}

static bool tc_local_sockaddr_valid(const struct sock *sk, const void *aux,
				    u32 aux_len)
{
	if (!aux || !aux_len)
		return false;

	if (sk->sk_family == PF_INET) {
		const struct sockaddr_in *sin = aux;

		if (aux_len != sizeof(*sin))
			return false;
		return sin->sin_family == AF_INET;
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == PF_INET6) {
		const struct sockaddr_in6 *sin6 = aux;

		if (aux_len != sizeof(*sin6))
			return false;
		return sin6->sin6_family == AF_INET6;
	}
#endif
	return false;
}

void trustcore_sock_abort_all(int err)
{
	struct tc_sock *tc;
	struct hlist_node *tmp;
	struct sock *sk;
	unsigned int bkt;

	if (err <= 0)
		err = ENETDOWN;

	for (;;) {
		tc = NULL;
		sk = NULL;
		spin_lock(&tc_requests_lock);
		for (bkt = 0; bkt < HASH_SIZE(tc_requests); bkt++) {
			hlist_for_each_entry_safe(tc, tmp, &tc_requests[bkt], req_node) {
				if (!tc->pending_req_id)
					continue;
				sk = &tc->inet.sk;
				sock_hold(sk);
				if (!hlist_unhashed(&tc->req_node))
					hlist_del_init(&tc->req_node);
				tc->pending_req_id = 0;
				break;
			}
			if (sk)
				break;
		}
		spin_unlock(&tc_requests_lock);

		if (!sk)
			break;

		/* tc_requests_lock must not be held when taking the socket lock. */
		lock_sock(sk);
		tc->pending_status = err;
		sk->sk_err = err;
		tc->closing = true;
		sk->sk_state = TCP_CLOSE;
		release_sock(sk);
		/* Invoke callbacks after unlocking to avoid re-entrancy issues. */
		sk->sk_state_change(sk);
		wake_up_interruptible(&tc->wait);
		sock_put(sk);
	}
}

static void tc_handle_inbound(const struct tc_net_desc *desc,
			      void *data,
			      u32 data_len,
			      void *aux,
			      u32 aux_len)
{
	switch (desc->type) {
	case TC_NET_DESC_CONNECT_RESP: {
		struct sock *sk = tc_find_request_sk(desc->req_id);
		struct tc_sock *tc;
		if (!sk) {
			kfree(data);
			kfree(aux);
			return;
		}
		tc = tc_sk(sk);
		if (desc->status == 0) {
			if (desc->stream_id && desc->stream_id != tc->stream_id)
				tc->stream_id = desc->stream_id;
			tc_register_stream(tc);
			tc->inet.sk.sk_state = TCP_ESTABLISHED;
			if (tc_local_sockaddr_valid(sk, aux, aux_len)) {
				memcpy(&tc->local, aux, aux_len);
				tc->local_len = aux_len;
			}
		} else {
			tc->peer_len = 0;
			tc->closing = true;
			tc->inet.sk.sk_state = TCP_CLOSE;
		}
		tc_complete_request(tc, desc->status);
		sock_put(sk);
		kfree(data);
		kfree(aux);
		return;
	}
	case TC_NET_DESC_DGRAM_BIND_RESP: {
		struct sock *sk = tc_find_request_sk(desc->req_id);
		struct tc_sock *tc;
		if (!sk) {
			kfree(data);
			kfree(aux);
			return;
		}
		tc = tc_sk(sk);
		if (desc->status == 0) {
			if (desc->stream_id && desc->stream_id != tc->stream_id)
				tc->stream_id = desc->stream_id;
			tc_register_stream(tc);
			tc->dgram_host_ready = true;
			if (tc_local_sockaddr_valid(sk, aux, aux_len)) {
				memcpy(&tc->local, aux, aux_len);
				tc->local_len = aux_len;
			}
		}
		tc_complete_request(tc, desc->status);
		sock_put(sk);
		kfree(data);
		kfree(aux);
		return;
	}
	case TC_NET_DESC_DGRAM_CONNECT_RESP: {
		struct sock *sk = tc_find_request_sk(desc->req_id);
		struct tc_sock *tc;
		if (!sk) {
			kfree(data);
			kfree(aux);
			return;
		}
		tc = tc_sk(sk);
		if (desc->status == 0) {
			if (desc->stream_id && desc->stream_id != tc->stream_id)
				tc->stream_id = desc->stream_id;
			tc_register_stream(tc);
			tc->dgram_host_ready = true;
			tc->dgram_connected = true;
			if (tc_local_sockaddr_valid(sk, aux, aux_len)) {
				memcpy(&tc->local, aux, aux_len);
				tc->local_len = aux_len;
			}
		} else {
			tc->peer_len = 0;
			tc->dgram_connected = false;
		}
		tc_complete_request(tc, desc->status);
		sock_put(sk);
		kfree(data);
		kfree(aux);
		return;
	}
	case TC_NET_DESC_LISTEN_RESP: {
		struct sock *sk = tc_find_request_sk(desc->req_id);
		struct tc_sock *tc;
		if (!sk) {
			kfree(data);
			kfree(aux);
			return;
		}
		tc = tc_sk(sk);
		if (desc->status == 0) {
			tc->listening = true;
			tc_register_listener(tc);
			tc->inet.sk.sk_state = TCP_LISTEN;
			if (tc_local_sockaddr_valid(sk, aux, aux_len)) {
				memcpy(&tc->local, aux, aux_len);
				tc->local_len = aux_len;
			}
		}
		tc_complete_request(tc, desc->status);
		sock_put(sk);
		kfree(data);
		kfree(aux);
		return;
	}
	case TC_NET_DESC_ACCEPT: {
		struct sock *lsk = tc_find_listener_sk(desc->listener_id);
		struct tc_sock *listener;
		struct tc_accept_entry *entry;

		if (!lsk) {
			kfree(data);
			kfree(aux);
			return;
		}
		listener = tc_sk(lsk);
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		if (!entry) {
			sock_put(lsk);
			kfree(data);
			kfree(aux);
			return;
		}
		entry->stream_id = desc->stream_id;
		INIT_LIST_HEAD(&entry->rx_queue);
		entry->rx_queued_bytes = 0;
		entry->rx_queued_bufs = 0;
		INIT_HLIST_NODE(&entry->node);
		if (aux && (aux_len == sizeof(struct sockaddr_in) ||
			    aux_len == sizeof(struct sockaddr_in6))) {
			memcpy(&entry->peer, aux, aux_len);
			entry->peer_len = aux_len;
		}
		spin_lock(&tc_pending_accepts_lock);
		hash_add(tc_pending_accepts, &entry->node, entry->stream_id);
		spin_unlock(&tc_pending_accepts_lock);
		spin_lock(&listener->accept_lock);
		list_add_tail(&entry->list, &listener->accept_queue);
		spin_unlock(&listener->accept_lock);
		pr_info("trustcore-sock: inbound ACCEPT listener_id=%llu stream_id=%llu peer_len=%u\n",
			desc->listener_id, desc->stream_id, entry->peer_len);
		listener->inet.sk.sk_state_change(&listener->inet.sk);
		wake_up_interruptible(&listener->wait);
		sock_put(lsk);
		kfree(data);
		kfree(aux);
		return;
	}
	case TC_NET_DESC_RECV: {
		/* RECV is handled in trustcore_net.c fast path; should not reach here */
		kfree(data);
		kfree(aux);
		return;
	}
	case TC_NET_DESC_CLOSE: {
		struct sock *sk = tc_find_stream_sk(desc->stream_id);
		struct tc_sock *tc;
		if (!sk) {
			kfree(data);
			kfree(aux);
			return;
		}
		tc = tc_sk(sk);
		tc->closing = true;
		tc->inet.sk.sk_err = desc->status;
		if (sk->sk_type == SOCK_STREAM)
			tc->inet.sk.sk_state = TCP_CLOSE;
		tc->inet.sk.sk_state_change(&tc->inet.sk);
		wake_up_interruptible(&tc->wait);
		sock_put(sk);
		kfree(data);
		kfree(aux);
		return;
	}
	default:
		kfree(data);
		kfree(aux);
		return;
	}
}

static int tc_sock_set_timeout(long *timeo_p, sockptr_t optval, int optlen)
{
	struct __kernel_sock_timeval tv;
	long val = MAX_SCHEDULE_TIMEOUT;

	if (sock_copy_user_timeval(&tv, optval, optlen, false))
		return -EFAULT;

	if (tv.tv_usec < 0 || tv.tv_usec >= USEC_PER_SEC)
		return -EDOM;

	if (tv.tv_sec < 0) {
		WRITE_ONCE(*timeo_p, 0);
		return 0;
	}

	if (tv.tv_sec || tv.tv_usec) {
		val = tv.tv_sec * HZ + DIV_ROUND_UP((unsigned long)tv.tv_usec,
						    USEC_PER_SEC / HZ);
	}

	WRITE_ONCE(*timeo_p, val);
	return 0;
}

static int tc_sock_get_timeout(long timeo, struct __kernel_sock_timeval *tv)
{
	if (timeo == MAX_SCHEDULE_TIMEOUT) {
		tv->tv_sec = 0;
		tv->tv_usec = 0;
		return sizeof(*tv);
	}
	tv->tv_sec = timeo / HZ;
	tv->tv_usec = (timeo % HZ) * (USEC_PER_SEC / HZ);
	return sizeof(*tv);
}

static int trustcore_dgram_bind_host(struct socket *sock, bool nonblock);

static int trustcore_init_sock(struct sock *sk)
{
	struct tc_sock *tc = tc_sk(sk);

	tc->stream_id = 0;
	tc->listener_id = 0;
	tc->pending_req_id = 0;
	tc->pending_status = 0;
	tc->closing = false;
	tc->listening = false;
	tc->dgram_connected = false;
	tc->dgram_host_ready = false;
	tc->peer_len = 0;
	tc->local_len = 0;
	init_waitqueue_head(&tc->wait);
	spin_lock_init(&tc->rx_lock);
	INIT_LIST_HEAD(&tc->rx_queue);
	tc->rx_queued_bytes = 0;
	tc->rx_queued_bufs = 0;
	spin_lock_init(&tc->accept_lock);
	INIT_LIST_HEAD(&tc->accept_queue);
	INIT_HLIST_NODE(&tc->stream_node);
	INIT_HLIST_NODE(&tc->listener_node);
	INIT_HLIST_NODE(&tc->req_node);
	return 0;
}

static void trustcore_destroy_sock(struct sock *sk)
{
	struct tc_sock *tc = tc_sk(sk);
	struct tc_rx_buf *buf, *tmp;
	struct tc_accept_entry *entry, *etmp;

	if (!hlist_unhashed(&tc->req_node))
		tc_unregister_request(tc);
	if (tc->stream_id && !hlist_unhashed(&tc->stream_node))
		tc_unregister_stream(tc);
	if (tc->listener_id && !hlist_unhashed(&tc->listener_node))
		tc_unregister_listener(tc);

	spin_lock(&tc->rx_lock);
	list_for_each_entry_safe(buf, tmp, &tc->rx_queue, list) {
		list_del(&buf->list);
		tc->rx_queued_bytes -= buf->len;
		tc->rx_queued_bufs--;
		kfree(buf);
	}
	spin_unlock(&tc->rx_lock);

	spin_lock(&tc->accept_lock);
	list_for_each_entry_safe(entry, etmp, &tc->accept_queue, list) {
		list_del(&entry->list);
		spin_lock(&tc_pending_accepts_lock);
		if (!hlist_unhashed(&entry->node))
			hlist_del_init(&entry->node);
		while (!list_empty(&entry->rx_queue)) {
			buf = list_first_entry(&entry->rx_queue, struct tc_rx_buf, list);
			list_del(&buf->list);
			kfree(buf);
		}
		spin_unlock(&tc_pending_accepts_lock);
		kfree(entry);
	}
	spin_unlock(&tc->accept_lock);
}

static int trustcore_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct tc_sock *tc = tc_sk(sock->sk);

	if (addr_len < sizeof(sa_family_t)) {
		return -EINVAL;
	}
	if (sock->ops->family == PF_INET) {
		if (addr->sa_family != AF_INET ||
		    addr_len != sizeof(struct sockaddr_in)) {
			return -EINVAL;
		}
	} else if (sock->ops->family == PF_INET6) {
		if (addr->sa_family != AF_INET6 ||
		    addr_len != sizeof(struct sockaddr_in6)) {
			return -EINVAL;
		}
	} else {
		return -EINVAL;
	}
	memcpy(&tc->local, addr, addr_len);
	tc->local_len = addr_len;
	if (sock->type == SOCK_DGRAM && trustcore_net_ready()) {
		int rc = trustcore_dgram_bind_host(sock, false);
		return rc;
	}
	return 0;
}

static int tc_dgram_prepare_local(struct socket *sock, struct tc_sock *tc)
{
	if (tc->local_len)
		return 0;

	if (sock->ops->family == PF_INET) {
		struct sockaddr_in sin = {};

		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
		sin.sin_port = 0;
		memcpy(&tc->local, &sin, sizeof(sin));
		tc->local_len = sizeof(sin);
		return 0;
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (sock->ops->family == PF_INET6) {
		struct sockaddr_in6 sin6 = {};

		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = in6addr_any;
		sin6.sin6_port = 0;
		memcpy(&tc->local, &sin6, sizeof(sin6));
		tc->local_len = sizeof(sin6);
		return 0;
	}
#endif
	return -EINVAL;
}

static int trustcore_dgram_bind_host(struct socket *sock, bool nonblock)
{
	struct sock *sk = sock->sk;
	struct tc_sock *tc = tc_sk(sk);
	struct tc_net_desc desc = {};
	struct {
		struct tc_net_origin origin;
		struct sockaddr_storage sa;
	} auxbuf;
	long timeout;
	long wait_rc;
	int rc;

	if (tc->dgram_host_ready)
		return 0;
	if (!trustcore_net_ready()) {
		return -ENETDOWN;
	}
	if (tc->pending_req_id) {
		if (nonblock)
			return -EAGAIN;
		timeout = sock_sndtimeo(sk, nonblock);
		wait_rc = wait_event_interruptible_timeout(tc->wait,
							   tc->pending_req_id == 0 || tc->closing ||
							   !trustcore_net_ready(),
							   timeout);
		if (wait_rc <= 0) {
			return wait_rc == 0 ? -ETIMEDOUT : (int)wait_rc;
		}
		if (!trustcore_net_ready())
			return -ENETDOWN;
		if (tc->pending_status) {
			return -tc->pending_status;
		}
		return tc->dgram_host_ready ? 0 : -EIO;
	}

	rc = tc_dgram_prepare_local(sock, tc);
	if (rc)
		return rc;

	if (!tc->stream_id)
		tc->stream_id = atomic64_inc_return(&tc_next_stream_id);
	tc->pending_status = 0;
	sk->sk_err = 0;

	desc.type = TC_NET_DESC_DGRAM_BIND;
	desc.stream_id = tc->stream_id;
	desc.req_id = atomic64_inc_return(&tc_next_req_id);
	desc.status = 0;
	desc.flags = TC_NET_DESC_F_ORIGIN;
	auxbuf.origin.tgid = (u32)current->tgid;
	auxbuf.origin.uid = (u32)from_kuid_munged(current_user_ns(), current_uid());
	auxbuf.origin.gid = (u32)from_kgid_munged(current_user_ns(), current_gid());
	auxbuf.origin.reserved = 0;
	memset(&auxbuf.sa, 0, sizeof(auxbuf.sa));
	memcpy(&auxbuf.sa, &tc->local, tc->local_len);

	tc_register_request(tc, desc.req_id);
	rc = trustcore_net_send_desc(&desc, NULL, 0, &auxbuf,
				     sizeof(auxbuf.origin) + tc->local_len,
				     nonblock);
	if (rc) {
		tc_unregister_request(tc);
		return rc;
	}

	if (nonblock)
		return -EAGAIN;

	timeout = sock_sndtimeo(sk, nonblock);
	wait_rc = wait_event_interruptible_timeout(tc->wait,
						   tc->pending_req_id == 0 || tc->closing ||
						   !trustcore_net_ready(),
						   timeout);
	if (wait_rc <= 0) {
		tc_unregister_request(tc);
		return wait_rc == 0 ? -ETIMEDOUT : (int)wait_rc;
	}
	if (!trustcore_net_ready()) {
		if (tc->pending_req_id)
			tc_unregister_request(tc);
		return -ENETDOWN;
	}
	if (tc->pending_status) {
		return -tc->pending_status;
	}
	return tc->dgram_host_ready ? 0 : -EIO;
}

static int trustcore_connect(struct socket *sock, struct sockaddr *addr,
			     int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct tc_sock *tc = tc_sk(sk);
	struct tc_net_desc desc = {};
	struct {
		struct tc_net_origin origin;
		struct sockaddr_storage sa;
	} auxbuf;
	bool nonblock = flags & O_NONBLOCK;
	long timeout;
	long wait_rc;
	int rc;

	if (sock->type == SOCK_DGRAM) {
		if (!trustcore_net_ready())
			return -ENETDOWN;
		if (addr_len < sizeof(sa_family_t))
			return -EINVAL;
		if (addr->sa_family == AF_UNSPEC)
			return -EINVAL;
		if (sock->ops->family == PF_INET) {
			if (addr->sa_family != AF_INET ||
			    addr_len != sizeof(struct sockaddr_in))
				return -EINVAL;
		} else if (sock->ops->family == PF_INET6) {
			if (addr->sa_family != AF_INET6 ||
			    addr_len != sizeof(struct sockaddr_in6))
				return -EINVAL;
		} else {
			return -EINVAL;
		}

		if (tc->local_len && !tc->dgram_host_ready) {
			rc = trustcore_dgram_bind_host(sock, nonblock);
			if (rc)
				return rc;
		}

		memcpy(&tc->peer, addr, addr_len);
		tc->peer_len = addr_len;
		tc->pending_status = 0;
		tc->dgram_connected = false;
		sk->sk_err = 0;

		if (!tc->stream_id)
			tc->stream_id = atomic64_inc_return(&tc_next_stream_id);
		desc.type = TC_NET_DESC_DGRAM_CONNECT;
		desc.stream_id = tc->stream_id;
		desc.req_id = atomic64_inc_return(&tc_next_req_id);
		desc.status = 0;
		desc.flags = TC_NET_DESC_F_ORIGIN;
		auxbuf.origin.tgid = (u32)current->tgid;
		auxbuf.origin.uid = (u32)from_kuid_munged(current_user_ns(), current_uid());
		auxbuf.origin.gid = (u32)from_kgid_munged(current_user_ns(), current_gid());
		auxbuf.origin.reserved = 0;
		memset(&auxbuf.sa, 0, sizeof(auxbuf.sa));
		memcpy(&auxbuf.sa, addr, addr_len);

		tc_register_request(tc, desc.req_id);
		rc = trustcore_net_send_desc(&desc, NULL, 0, &auxbuf,
					     sizeof(auxbuf.origin) + addr_len, nonblock);
		if (rc) {
			tc_unregister_request(tc);
			tc->peer_len = 0;
			return rc;
		}

		if (nonblock)
			return -EINPROGRESS;

		timeout = sock_sndtimeo(sk, flags & O_NONBLOCK);
		wait_rc = wait_event_interruptible_timeout(tc->wait,
							   tc->pending_req_id == 0 || tc->closing ||
							   !trustcore_net_ready(),
							   timeout);
		if (wait_rc <= 0) {
			tc_unregister_request(tc);
			tc->peer_len = 0;
			return wait_rc == 0 ? -ETIMEDOUT : (int)wait_rc;
		}
		if (!trustcore_net_ready()) {
			if (tc->pending_req_id)
				tc_unregister_request(tc);
			tc->peer_len = 0;
			return -ENETDOWN;
		}
		if (tc->pending_status) {
			tc->peer_len = 0;
			return -tc->pending_status;
		}
		return 0;
	}

	if (!trustcore_net_ready())
		return -ENETDOWN;
	if (sk->sk_state == TCP_ESTABLISHED)
		return -EISCONN;
	if (addr_len < sizeof(sa_family_t))
		return -EINVAL;
	if (addr->sa_family == AF_UNSPEC)
		return -EINVAL;
	if (sock->ops->family == PF_INET) {
		if (addr->sa_family != AF_INET ||
		    addr_len != sizeof(struct sockaddr_in))
			return -EINVAL;
	} else if (sock->ops->family == PF_INET6) {
		if (addr->sa_family != AF_INET6 ||
		    addr_len != sizeof(struct sockaddr_in6))
			return -EINVAL;
	} else {
		return -EINVAL;
	}

	memcpy(&tc->peer, addr, addr_len);
	tc->peer_len = addr_len;
	tc->pending_status = 0;
	sk->sk_err = 0;

	if (!tc->stream_id)
		tc->stream_id = atomic64_inc_return(&tc_next_stream_id);
	desc.type = TC_NET_DESC_CONNECT;
	desc.stream_id = tc->stream_id;
	desc.req_id = atomic64_inc_return(&tc_next_req_id);
	desc.status = 0;
	desc.flags = TC_NET_DESC_F_ORIGIN;
	auxbuf.origin.tgid = (u32)current->tgid;
	auxbuf.origin.uid = (u32)from_kuid_munged(current_user_ns(), current_uid());
	auxbuf.origin.gid = (u32)from_kgid_munged(current_user_ns(), current_gid());
	auxbuf.origin.reserved = 0;
	memset(&auxbuf.sa, 0, sizeof(auxbuf.sa));
	memcpy(&auxbuf.sa, addr, addr_len);

	tc_register_request(tc, desc.req_id);
	rc = trustcore_net_send_desc(&desc, NULL, 0, &auxbuf, sizeof(auxbuf.origin) + addr_len, nonblock);
	if (rc) {
		tc_unregister_request(tc);
		tc->peer_len = 0;
		return rc;
	}

	sk->sk_state = TCP_SYN_SENT;
	if (nonblock)
		return -EINPROGRESS;

	timeout = sock_sndtimeo(sk, flags & O_NONBLOCK);
	wait_rc = wait_event_interruptible_timeout(tc->wait,
						   tc->pending_req_id == 0 || tc->closing ||
						   !trustcore_net_ready(),
						   timeout);
	if (wait_rc <= 0) {
		tc_unregister_request(tc);
		tc->peer_len = 0;
		return wait_rc == 0 ? -ETIMEDOUT : (int)wait_rc;
	}
	if (!trustcore_net_ready()) {
		if (tc->pending_req_id)
			tc_unregister_request(tc);
		tc->peer_len = 0;
		return -ENETDOWN;
	}
	if (tc->pending_status) {
		tc->peer_len = 0;
		return -tc->pending_status;
	}
	return 0;
}

static int trustcore_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct tc_sock *tc = tc_sk(sk);
	struct tc_net_desc desc = {};
	struct {
		struct tc_net_origin origin;
		struct sockaddr_storage sa;
	} auxbuf;
	long timeout;
	long wait_rc;
	int rc;

	if (sock->type == SOCK_DGRAM)
		return -EOPNOTSUPP;
	if (!trustcore_net_ready())
		return -ENETDOWN;
	if (!tc->local_len) {
		if (sock->ops->family == PF_INET) {
			struct sockaddr_in sin = {};

			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = htonl(INADDR_ANY);
			sin.sin_port = 0;
			memcpy(&tc->local, &sin, sizeof(sin));
			tc->local_len = sizeof(sin);
		} else if (sock->ops->family == PF_INET6) {
			struct sockaddr_in6 sin6 = {};

			sin6.sin6_family = AF_INET6;
			sin6.sin6_addr = in6addr_any;
			sin6.sin6_port = 0;
			memcpy(&tc->local, &sin6, sizeof(sin6));
			tc->local_len = sizeof(sin6);
		} else {
			return -EINVAL;
		}
	}
	if (sock->ops->family == PF_INET) {
		if (tc->local.ss_family != AF_INET ||
		    tc->local_len != sizeof(struct sockaddr_in))
			return -EINVAL;
	} else if (sock->ops->family == PF_INET6) {
		if (tc->local.ss_family != AF_INET6 ||
		    tc->local_len != sizeof(struct sockaddr_in6))
			return -EINVAL;
	} else {
		return -EINVAL;
	}
	if (tc->listening)
		return 0;
	tc->pending_status = 0;
	sk->sk_err = 0;

	if (!tc->listener_id)
		tc->listener_id = atomic64_inc_return(&tc_next_listener_id);
	desc.type = TC_NET_DESC_LISTEN;
	desc.stream_id = tc->listener_id;
	desc.req_id = atomic64_inc_return(&tc_next_req_id);
	desc.flags = TC_NET_DESC_F_ORIGIN;
	{
		int bl = backlog;

		if (bl < 0)
			bl = 0;
		if (bl > SOMAXCONN)
			bl = SOMAXCONN;
		desc.credit = (u32)bl;
	}
	auxbuf.origin.tgid = (u32)current->tgid;
	auxbuf.origin.uid = (u32)from_kuid_munged(current_user_ns(), current_uid());
	auxbuf.origin.gid = (u32)from_kgid_munged(current_user_ns(), current_gid());
	auxbuf.origin.reserved = 0;
	memset(&auxbuf.sa, 0, sizeof(auxbuf.sa));
	memcpy(&auxbuf.sa, &tc->local, tc->local_len);

	tc_register_request(tc, desc.req_id);
	rc = trustcore_net_send_desc(&desc, NULL, 0, &auxbuf, sizeof(auxbuf.origin) + tc->local_len, false);
	if (rc) {
		tc_unregister_request(tc);
		return rc;
	}

	timeout = sock_sndtimeo(sk, 0);
	wait_rc = wait_event_interruptible_timeout(tc->wait,
						   tc->pending_req_id == 0 || tc->closing ||
						   !trustcore_net_ready(),
						   timeout);
	if (wait_rc <= 0) {
		tc_unregister_request(tc);
		return wait_rc == 0 ? -ETIMEDOUT : (int)wait_rc;
	}
	if (!trustcore_net_ready()) {
		if (tc->pending_req_id)
			tc_unregister_request(tc);
		return -ENETDOWN;
	}
	if (tc->pending_status)
		return -tc->pending_status;
	return 0;
}

static int trustcore_accept(struct socket *sock, struct socket *newsock,
			    struct proto_accept_arg *arg)
{
	struct sock *sk = sock->sk;
	struct tc_sock *listener = tc_sk(sk);
	struct tc_accept_entry *entry;
	struct sock *newsk;
	struct tc_sock *child;
	bool nonblock = arg->flags & O_NONBLOCK;
	long timeout;
	long wait_rc;

	if (sock->type == SOCK_DGRAM)
		return -EOPNOTSUPP;
	if (!listener->listening)
		return -EINVAL;

	for (;;) {
		spin_lock(&listener->accept_lock);
		entry = list_first_entry_or_null(&listener->accept_queue,
						 struct tc_accept_entry, list);
		if (entry)
			list_del(&entry->list);
		spin_unlock(&listener->accept_lock);

		if (entry)
			break;

		if (nonblock)
			return -EAGAIN;

		timeout = sock_rcvtimeo(sk, arg->flags & O_NONBLOCK);
		wait_rc = wait_event_interruptible_timeout(listener->wait,
							   !list_empty(&listener->accept_queue) || listener->closing,
							   timeout);
		if (wait_rc <= 0)
			return wait_rc == 0 ? -ETIMEDOUT : (int)wait_rc;
	}

	newsk = sk_alloc(sock_net(sk), sock->ops->family, GFP_KERNEL, &trustcore_proto, arg->kern);
	if (!newsk) {
		kfree(entry);
		return -ENOMEM;
	}
	sock_init_data(newsock, newsk);
	newsock->ops = sock->ops;
	newsk->sk_rcvtimeo = sk->sk_rcvtimeo;
	newsk->sk_sndtimeo = sk->sk_sndtimeo;
	WRITE_ONCE(newsk->sk_rcvbuf, READ_ONCE(sk->sk_rcvbuf));
	WRITE_ONCE(newsk->sk_sndbuf, READ_ONCE(sk->sk_sndbuf));
	newsk->sk_userlocks = sk->sk_userlocks;
	newsk->sk_reuse = sk->sk_reuse;
	newsk->sk_reuseport = sk->sk_reuseport;
	if (sock_flag(sk, SOCK_KEEPOPEN))
		sock_set_flag(newsk, SOCK_KEEPOPEN);
	if (sock_flag(sk, SOCK_LINGER)) {
		sock_set_flag(newsk, SOCK_LINGER);
		WRITE_ONCE(newsk->sk_lingertime, READ_ONCE(sk->sk_lingertime));
	}

	child = tc_sk(newsk);
	child->stream_id = entry->stream_id;
	child->listening = false;
	child->inet.sk.sk_state = TCP_ESTABLISHED;
	if (entry->peer_len) {
		memcpy(&child->peer, &entry->peer, entry->peer_len);
		child->peer_len = entry->peer_len;
	}
	if (listener->local_len) {
		memcpy(&child->local, &listener->local, listener->local_len);
		child->local_len = listener->local_len;
	}
	tc_register_stream(child);
	{
		struct list_head pending;
		u32 pending_bytes = 0;
		u32 pending_bufs = 0;

		INIT_LIST_HEAD(&pending);
		spin_lock(&tc_pending_accepts_lock);
		if (!hlist_unhashed(&entry->node))
			hlist_del_init(&entry->node);
		if (!list_empty(&entry->rx_queue)) {
			list_splice_init(&entry->rx_queue, &pending);
			pending_bytes = entry->rx_queued_bytes;
			pending_bufs = entry->rx_queued_bufs;
			entry->rx_queued_bytes = 0;
			entry->rx_queued_bufs = 0;
		}
		spin_unlock(&tc_pending_accepts_lock);

		if (!list_empty(&pending)) {
			spin_lock(&child->rx_lock);
			list_splice_tail(&pending, &child->rx_queue);
			child->rx_queued_bytes += pending_bytes;
			child->rx_queued_bufs += pending_bufs;
			spin_unlock(&child->rx_lock);
			child->inet.sk.sk_state_change(&child->inet.sk);
			wake_up_interruptible(&child->wait);
		}
		pr_info("trustcore-sock: accept complete stream_id=%llu pending_bytes=%u pending_bufs=%u\n",
			child->stream_id, pending_bytes, pending_bufs);
	}
	kfree(entry);
	return 0;
}

static int trustcore_getname(struct socket *sock, struct sockaddr *addr, int peer)
{
	struct tc_sock *tc = tc_sk(sock->sk);
	int len = peer ? tc->peer_len : tc->local_len;

	if (peer) {
		if (sock->type == SOCK_DGRAM) {
			if (!tc->peer_len)
				return -ENOTCONN;
		} else if (sock->sk->sk_state != TCP_ESTABLISHED) {
			return -ENOTCONN;
		}
		if (!tc->peer_len)
			return -ENOTCONN;
		memcpy(addr, &tc->peer, tc->peer_len);
		return len;
	}
	if (!tc->local_len)
		return -EINVAL;
	memcpy(addr, &tc->local, tc->local_len);
	return len;
}

static __poll_t trustcore_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct tc_sock *tc = tc_sk(sk);
	__poll_t mask = 0;

	poll_wait(file, sk_sleep(sk), wait);

	if (tc->listening) {
		spin_lock(&tc->accept_lock);
		if (!list_empty(&tc->accept_queue))
			mask |= POLLIN | POLLRDNORM;
		spin_unlock(&tc->accept_lock);
	} else {
		spin_lock(&tc->rx_lock);
		if (!list_empty(&tc->rx_queue))
			mask |= POLLIN | POLLRDNORM;
		spin_unlock(&tc->rx_lock);
	}

	if ((sock->type == SOCK_DGRAM || sk->sk_state == TCP_ESTABLISHED) &&
	    trustcore_net_tx_ready(TRUSTCORE_TX_READY_MIN))
		mask |= POLLOUT | POLLWRNORM;
	if (sk->sk_err)
		mask |= POLLERR;
	if (tc->closing)
		mask |= POLLHUP;
	return mask;
}

static int trustcore_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	return -ENOIOCTLCMD;
}

static int trustcore_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	struct tc_sock *tc = tc_sk(sk);
	struct tc_net_desc desc = {};

	if (sock->type == SOCK_DGRAM) {
		if (tc->stream_id && trustcore_net_ready()) {
			desc.type = TC_NET_DESC_CLOSE;
			desc.stream_id = tc->stream_id;
			desc.status = 0;
			trustcore_net_send_desc(&desc, NULL, 0, NULL, 0, true);
		}
		tc->closing = true;
		return 0;
	}

	if (!tc->stream_id || !trustcore_net_ready())
		return 0;

	desc.type = TC_NET_DESC_CLOSE;
	desc.stream_id = tc->stream_id;
	desc.status = 0;
	trustcore_net_send_desc(&desc, NULL, 0, NULL, 0, true);
	tc->closing = true;
	sk->sk_state = TCP_CLOSE;
	return 0;
}

static int trustcore_setsockopt(struct socket *sock, int level, int optname,
				sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct linger ling;
	int val;
	int valbool;
	int ret = 0;

	if (level != SOL_SOCKET)
		return -ENOPROTOOPT;

	/* Options are stored locally for compatibility; not forwarded to userspace. */
	switch (optname) {
	case SO_RCVTIMEO_NEW:
	case SO_RCVTIMEO_OLD:
		return tc_sock_set_timeout(&sk->sk_rcvtimeo, optval, optlen);
	case SO_SNDTIMEO_NEW:
	case SO_SNDTIMEO_OLD:
		return tc_sock_set_timeout(&sk->sk_sndtimeo, optval, optlen);
	case SO_LINGER:
		if (optlen < sizeof(ling))
			return -EINVAL;
		if (copy_from_sockptr(&ling, optval, sizeof(ling)))
			return -EFAULT;
		sockopt_lock_sock(sk);
		if (!ling.l_onoff) {
			sock_reset_flag(sk, SOCK_LINGER);
		} else {
			unsigned long t_sec = ling.l_linger;

			if (t_sec >= MAX_SCHEDULE_TIMEOUT / HZ)
				WRITE_ONCE(sk->sk_lingertime, MAX_SCHEDULE_TIMEOUT);
			else
				WRITE_ONCE(sk->sk_lingertime, t_sec * HZ);
			sock_set_flag(sk, SOCK_LINGER);
		}
		sockopt_release_sock(sk);
		return 0;
	default:
		break;
	}

	if (optlen < sizeof(int))
		return -EINVAL;
	if (copy_from_sockptr(&val, optval, sizeof(int)))
		return -EFAULT;
	valbool = !!val;

	sockopt_lock_sock(sk);
	switch (optname) {
	case SO_KEEPALIVE:
		sock_valbool_flag(sk, SOCK_KEEPOPEN, valbool);
		break;
	case SO_REUSEADDR:
		sk->sk_reuse = valbool ? SK_CAN_REUSE : SK_NO_REUSE;
		break;
	case SO_REUSEPORT:
		sk->sk_reuseport = valbool;
		break;
	case SO_SNDBUF:
		val = min_t(u32, val, READ_ONCE(sysctl_wmem_max));
		val = min_t(int, val, INT_MAX / 2);
		sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
		WRITE_ONCE(sk->sk_sndbuf,
			   max_t(int, val * 2, SOCK_MIN_SNDBUF));
		sk->sk_write_space(sk);
		break;
	case SO_RCVBUF:
		val = min_t(u32, val, READ_ONCE(sysctl_rmem_max));
		val = min_t(int, val, INT_MAX / 2);
		sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
		WRITE_ONCE(sk->sk_rcvbuf,
			   max_t(int, val * 2, SOCK_MIN_RCVBUF));
		break;
	default:
		ret = -ENOPROTOOPT;
		break;
	}
	sockopt_release_sock(sk);
	return ret;
}

static int trustcore_getsockopt(struct socket *sock, int level, int optname,
				char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct __kernel_sock_timeval tv;
	struct linger ling;
	int len;
	int err = 0;
	int val;

	if (level != SOL_SOCKET)
		return -ENOPROTOOPT;

	switch (optname) {
	case SO_ERROR:
		val = sock_error(sk);
		len = sizeof(val);
		if (copy_to_user(optval, &val, len))
			err = -EFAULT;
		if (put_user(len, optlen))
			err = -EFAULT;
		return err;
	case SO_RCVTIMEO_NEW:
	case SO_RCVTIMEO_OLD:
		len = tc_sock_get_timeout(READ_ONCE(sk->sk_rcvtimeo), &tv);
		if (copy_to_user(optval, &tv, len))
			return -EFAULT;
		if (put_user(len, optlen))
			return -EFAULT;
		return 0;
	case SO_SNDTIMEO_NEW:
	case SO_SNDTIMEO_OLD:
		len = tc_sock_get_timeout(READ_ONCE(sk->sk_sndtimeo), &tv);
		if (copy_to_user(optval, &tv, len))
			return -EFAULT;
		if (put_user(len, optlen))
			return -EFAULT;
		return 0;
	case SO_KEEPALIVE:
		val = sock_flag(sk, SOCK_KEEPOPEN);
		len = sizeof(val);
		break;
	case SO_REUSEADDR:
		val = sk->sk_reuse;
		len = sizeof(val);
		break;
	case SO_REUSEPORT:
		val = sk->sk_reuseport;
		len = sizeof(val);
		break;
	case SO_SNDBUF:
		val = READ_ONCE(sk->sk_sndbuf);
		len = sizeof(val);
		break;
	case SO_RCVBUF:
		val = READ_ONCE(sk->sk_rcvbuf);
		len = sizeof(val);
		break;
	case SO_LINGER:
		ling.l_onoff = sock_flag(sk, SOCK_LINGER);
		ling.l_linger = READ_ONCE(sk->sk_lingertime) / HZ;
		len = sizeof(ling);
		if (copy_to_user(optval, &ling, len))
			return -EFAULT;
		if (put_user(len, optlen))
			return -EFAULT;
		return 0;
	default:
		return -ENOPROTOOPT;
	}

	if (copy_to_user(optval, &val, len))
		err = -EFAULT;
	if (put_user(len, optlen))
		err = -EFAULT;
	return err;
}

static int trustcore_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct tc_sock *tc = tc_sk(sk);
	size_t remaining = len;
	size_t total = 0;
	bool nonblock = msg->msg_flags & MSG_DONTWAIT;
	int rc;

	if (sock->type == SOCK_DGRAM) {
		const struct sockaddr *daddr = NULL;
		u32 daddr_len = 0;
		u32 max_payload;

		if (!trustcore_net_ready()) {
			return -ENETDOWN;
		}
		if (!len)
			return 0;

		if (msg->msg_name && msg->msg_namelen) {
			const struct sockaddr *sa = msg->msg_name;

			if (msg->msg_namelen < sizeof(sa_family_t)) {
				return -EINVAL;
			}
			if (sock->ops->family == PF_INET) {
				if (sa->sa_family != AF_INET ||
				    msg->msg_namelen != sizeof(struct sockaddr_in)) {
					return -EINVAL;
				}
			} else if (sock->ops->family == PF_INET6) {
				if (sa->sa_family != AF_INET6 ||
				    msg->msg_namelen != sizeof(struct sockaddr_in6)) {
					return -EINVAL;
				}
			} else {
				return -EINVAL;
			}
			daddr = sa;
			daddr_len = msg->msg_namelen;
		} else {
			if (!tc->dgram_connected || !tc->peer_len) {
				return -ENOTCONN;
			}
		}

		if (!tc->stream_id)
			tc->stream_id = atomic64_inc_return(&tc_next_stream_id);

		if (!tc->dgram_host_ready) {
			rc = trustcore_dgram_bind_host(sock, nonblock);
			if (rc) {
				return rc == -ENOSPC ? -EAGAIN : rc;
			}
		}

		max_payload = trustcore_net_max_payload();
		if (!max_payload) {
			return -ENETDOWN;
		}
		if (len > max_payload) {
			return -EMSGSIZE;
		}

		{
			struct tc_net_desc desc = {};

			desc.type = TC_NET_DESC_DGRAM_SEND;
			desc.stream_id = tc->stream_id;
			desc.req_id = 0;
			desc.status = 0;
			desc.flags = 0;
			rc = trustcore_net_send_desc_iter(&desc, &msg->msg_iter,
							  (u32)len,
							  daddr, daddr_len,
							  nonblock);
			if (rc) {
				if (rc == -ENOSPC)
					rc = -EAGAIN;
				return rc;
			}
		}

		return (int)len;
	}

	if (!trustcore_net_ready())
		return -ENETDOWN;
	if (sk->sk_state != TCP_ESTABLISHED || !tc->stream_id)
		return -ENOTCONN;

	while (remaining) {
		u32 max_payload = trustcore_net_max_payload();
		u32 chunk;
		struct tc_net_desc desc = {};
		if (!max_payload)
			return -ENETDOWN;
		chunk = min_t(u32, remaining, max_payload);
		desc.type = TC_NET_DESC_SEND;
		desc.stream_id = tc->stream_id;
		desc.req_id = 0;
		desc.status = 0;
		rc = trustcore_net_send_desc_iter(&desc, &msg->msg_iter, chunk,
						  NULL, 0, nonblock);
		if (rc) {
			if (rc == -ENOSPC)
				rc = -EAGAIN;
			return total ? (int)total : rc;
		}
		total += chunk;
		remaining -= chunk;
	}

	return (int)total;
}

static int trustcore_recvmsg(struct socket *sock, struct msghdr *msg, size_t len, int flags)
{
	struct sock *sk = sock->sk;
	struct tc_sock *tc = tc_sk(sk);
	struct tc_rx_buf *buf;
	size_t copied = 0;
	long timeout;
	long wait_rc;
	int rc;

	if (sock->type == SOCK_DGRAM) {
		if (!trustcore_net_ready())
			return -ENETDOWN;

		if (!tc->dgram_host_ready) {
			rc = trustcore_dgram_bind_host(sock, flags & MSG_DONTWAIT);
			if (rc)
				return rc;
		}

		for (;;) {
			spin_lock(&tc->rx_lock);
			buf = list_first_entry_or_null(&tc->rx_queue, struct tc_rx_buf, list);
			if (buf)
				list_del(&buf->list);
			spin_unlock(&tc->rx_lock);

			if (buf)
				break;

			if (flags & MSG_DONTWAIT)
				return -EAGAIN;

			timeout = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
			wait_rc = wait_event_interruptible_timeout(tc->wait,
								   !list_empty(&tc->rx_queue) || tc->closing,
								   timeout);
			if (wait_rc <= 0)
				return wait_rc == 0 ? -ETIMEDOUT : (int)wait_rc;
			if (tc->closing)
				return 0;
		}

		pr_info("trustcore-sock: recvmsg dgram stream_id=%llu buf_len=%u\n",
			tc->stream_id, buf->len);
		if (len > buf->len)
			len = buf->len;
		if (copy_to_iter(buf->data, len, &msg->msg_iter) != len) {
			spin_lock(&tc->rx_lock);
			tc->rx_queued_bytes -= buf->len;
			tc->rx_queued_bufs--;
			spin_unlock(&tc->rx_lock);
			kfree(buf);
			return -EFAULT;
		}
		copied = len;
		if (buf->addr_len && msg->msg_name) {
			if (msg->msg_namelen < buf->addr_len) {
				spin_lock(&tc->rx_lock);
				tc->rx_queued_bytes -= buf->len;
				tc->rx_queued_bufs--;
				spin_unlock(&tc->rx_lock);
				kfree(buf);
				return -EINVAL;
			}
			memcpy(msg->msg_name, &buf->addr, buf->addr_len);
			msg->msg_namelen = buf->addr_len;
		}
		if (len < buf->len)
			msg->msg_flags |= MSG_TRUNC;
		spin_lock(&tc->rx_lock);
		tc->rx_queued_bytes -= buf->len;
		tc->rx_queued_bufs--;
		spin_unlock(&tc->rx_lock);
		kfree(buf);
		return (int)copied;
	}

	if (!trustcore_net_ready())
		return -ENETDOWN;

	for (;;) {
		spin_lock(&tc->rx_lock);
		buf = list_first_entry_or_null(&tc->rx_queue, struct tc_rx_buf, list);
		if (buf)
			list_del(&buf->list);
		spin_unlock(&tc->rx_lock);

		if (buf)
			break;

		if (flags & MSG_DONTWAIT)
			return -EAGAIN;

		timeout = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
		wait_rc = wait_event_interruptible_timeout(tc->wait,
							   !list_empty(&tc->rx_queue) || tc->closing,
							   timeout);
		if (wait_rc <= 0)
			return wait_rc == 0 ? -ETIMEDOUT : (int)wait_rc;
		if (tc->closing)
			return 0;
	}

	pr_info("trustcore-sock: recvmsg stream_id=%llu buf_len=%u offset=%u\n",
		tc->stream_id, buf->len, buf->offset);
	if (len > buf->len - buf->offset)
		len = buf->len - buf->offset;
	if (copy_to_iter(buf->data + buf->offset, len, &msg->msg_iter) != len) {
		spin_lock(&tc->rx_lock);
		tc->rx_queued_bytes -= buf->len;
		tc->rx_queued_bufs--;
		spin_unlock(&tc->rx_lock);
		kfree(buf);
		return -EFAULT;
	}
	copied = len;
	buf->offset += len;
	if (buf->offset < buf->len) {
		spin_lock(&tc->rx_lock);
		list_add(&buf->list, &tc->rx_queue);
		spin_unlock(&tc->rx_lock);
	} else {
		spin_lock(&tc->rx_lock);
		tc->rx_queued_bytes -= buf->len;
		tc->rx_queued_bufs--;
		spin_unlock(&tc->rx_lock);
		kfree(buf);
	}

	return (int)copied;
}

static int trustcore_proto_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	if (!sk->sk_socket)
		return -EINVAL;
	return trustcore_sendmsg(sk->sk_socket, msg, len);
}

static int trustcore_proto_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
{
	int rc;

	if (!sk->sk_socket)
		return -EINVAL;
	rc = trustcore_recvmsg(sk->sk_socket, msg, len, flags);
	if (rc >= 0 && addr_len) {
		if (sk->sk_socket->type == SOCK_DGRAM)
			*addr_len = msg->msg_namelen;
		else
			*addr_len = 0;
	}
	return rc;
}

static int trustcore_proto_setsockopt(struct sock *sk, int level, int optname,
				      sockptr_t optval, unsigned int optlen)
{
	if (!sk->sk_socket)
		return -EINVAL;
	return trustcore_setsockopt(sk->sk_socket, level, optname, optval, optlen);
}

static int trustcore_proto_getsockopt(struct sock *sk, int level, int optname,
				      char __user *optval, int __user *optlen)
{
	if (!sk->sk_socket)
		return -EINVAL;
	return trustcore_getsockopt(sk->sk_socket, level, optname, optval, optlen);
}

static int trustcore_hash(struct sock *sk)
{
	return 0;
}

static void trustcore_unhash(struct sock *sk)
{
}

static int trustcore_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	kfree_skb(skb);
	return 0;
}

static void trustcore_proto_close(struct sock *sk, long timeout)
{
	struct tc_sock *tc = tc_sk(sk);
	struct tc_net_desc desc = {};

	(void)timeout;
	if (tc->stream_id && trustcore_net_ready()) {
		desc.type = TC_NET_DESC_CLOSE;
		desc.stream_id = tc->stream_id;
		desc.status = 0;
		trustcore_net_send_desc(&desc, NULL, 0, NULL, 0, true);
	}
	tc->closing = true;
	sk->sk_state = TCP_CLOSE;
	sk_common_release(sk);
}

static bool trustcore_net_cgroup_match(struct task_struct *task)
{
	struct cgroup *task_cgrp;
	struct tc_cgroup_entry *entry;
	bool matched = false;

	rcu_read_lock();
	task_cgrp = task_dfl_cgroup(task);
	if (!task_cgrp) {
		rcu_read_unlock();
		return false;
	}

	mutex_lock(&tc_cgroup_lock);
	list_for_each_entry(entry, &tc_cgroup_list, list) {
		if (cgroup_is_descendant(task_cgrp, entry->cgrp)) {
			matched = true;
			break;
		}
	}
	mutex_unlock(&tc_cgroup_lock);
	rcu_read_unlock();
	return matched;
}

int trustcore_net_cgroup_add(int fd, u64 *out_id)
{
	struct cgroup *cgrp;
	struct tc_cgroup_entry *entry;
	u64 id;

	if (fd < 0)
		return -EINVAL;

	cgrp = cgroup_get_from_fd(fd);
	if (IS_ERR(cgrp))
		return PTR_ERR(cgrp);

	id = cgroup_id(cgrp);

	mutex_lock(&tc_cgroup_lock);
	list_for_each_entry(entry, &tc_cgroup_list, list) {
		if (entry->id == id) {
			mutex_unlock(&tc_cgroup_lock);
			if (out_id)
				*out_id = id;
			cgroup_put(cgrp);
			return 0;
		}
	}
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		mutex_unlock(&tc_cgroup_lock);
		cgroup_put(cgrp);
		return -ENOMEM;
	}
	entry->cgrp = cgrp;
	entry->id = id;
	list_add_tail(&entry->list, &tc_cgroup_list);
	mutex_unlock(&tc_cgroup_lock);

	if (out_id)
		*out_id = id;
	return 0;
}
EXPORT_SYMBOL_GPL(trustcore_net_cgroup_add);

int trustcore_net_cgroup_del(u64 cgroup_id)
{
	struct tc_cgroup_entry *entry;
	struct tc_cgroup_entry *tmp;
	int rc = -ENOENT;

	mutex_lock(&tc_cgroup_lock);
	list_for_each_entry_safe(entry, tmp, &tc_cgroup_list, list) {
		if (entry->id == cgroup_id) {
			list_del(&entry->list);
			cgroup_put(entry->cgrp);
			kfree(entry);
			rc = 0;
			break;
		}
	}
	mutex_unlock(&tc_cgroup_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(trustcore_net_cgroup_del);

void trustcore_net_cgroup_clear(void)
{
	struct tc_cgroup_entry *entry;
	struct tc_cgroup_entry *tmp;

	mutex_lock(&tc_cgroup_lock);
	list_for_each_entry_safe(entry, tmp, &tc_cgroup_list, list) {
		list_del(&entry->list);
		cgroup_put(entry->cgrp);
		kfree(entry);
	}
	mutex_unlock(&tc_cgroup_lock);
}
EXPORT_SYMBOL_GPL(trustcore_net_cgroup_clear);

bool trustcore_net_should_intercept(int sock_type, int protocol)
{
	int mode = READ_ONCE(trustcore_intercept_mode);
	uid_t uid;
	gid_t gid;

	if (sock_type == SOCK_STREAM) {
		if (protocol != 0 && protocol != IPPROTO_TCP)
			return false;
	} else if (sock_type == SOCK_DGRAM) {
		if (protocol != 0 && protocol != IPPROTO_UDP)
			return false;
	} else {
		return false;
	}

	/* Fail-closed: intercept even when control plane is not ready. */
	switch (mode) {
	case TRUSTCORE_INTERCEPT_ON:
		return true;
	case TRUSTCORE_INTERCEPT_UID:
		if (trustcore_intercept_uid < 0)
			return false;
		uid = from_kuid_munged(current_user_ns(), current_uid());
		return uid == (uid_t)trustcore_intercept_uid;
	case TRUSTCORE_INTERCEPT_GID:
		if (trustcore_intercept_gid < 0)
			return false;
		gid = from_kgid_munged(current_user_ns(), current_gid());
		return gid == (gid_t)trustcore_intercept_gid;
	case TRUSTCORE_INTERCEPT_CGROUP:
		return trustcore_net_cgroup_match(current);
	case TRUSTCORE_INTERCEPT_OFF:
	default:
		return false;
	}
}
EXPORT_SYMBOL_GPL(trustcore_net_should_intercept);

struct proto trustcore_proto = {
	.name = "TRUSTCORE",
	.owner = THIS_MODULE,
	.close = trustcore_proto_close,
	.connect = NULL,
	.disconnect = NULL,
	.accept = NULL,
	.ioctl = NULL,
	.init = trustcore_init_sock,
	.destroy = trustcore_destroy_sock,
	.shutdown = NULL,
	.setsockopt = trustcore_proto_setsockopt,
	.getsockopt = trustcore_proto_getsockopt,
	.sendmsg = trustcore_proto_sendmsg,
	.recvmsg = trustcore_proto_recvmsg,
	.backlog_rcv = trustcore_backlog_rcv,
	.hash = trustcore_hash,
	.unhash = trustcore_unhash,
	.get_port = NULL,
	.max_header = 0,
	.obj_size = sizeof(struct tc_sock),
#if IS_ENABLED(CONFIG_IPV6)
	.ipv6_pinfo_offset = offsetof(struct tc_sock, inet6),
#endif
	.slab_flags = SLAB_TYPESAFE_BY_RCU,
	.no_autobind = true,
};
EXPORT_SYMBOL_GPL(trustcore_proto);

const struct proto_ops trustcore_inet_ops = {
	.family = PF_INET,
	.owner = THIS_MODULE,
	.release = inet_release,
	.bind = trustcore_bind,
	.connect = trustcore_connect,
	.socketpair = sock_no_socketpair,
	.accept = trustcore_accept,
	.getname = trustcore_getname,
	.poll = trustcore_poll,
	.ioctl = trustcore_ioctl,
	.listen = trustcore_listen,
	.shutdown = trustcore_shutdown,
	.setsockopt = trustcore_setsockopt,
	.getsockopt = trustcore_getsockopt,
	.sendmsg = trustcore_sendmsg,
	.recvmsg = trustcore_recvmsg,
	.mmap = sock_no_mmap,
};
EXPORT_SYMBOL_GPL(trustcore_inet_ops);

const struct proto_ops trustcore_inet6_ops = {
	.family = PF_INET6,
	.owner = THIS_MODULE,
	.release = inet_release,
	.bind = trustcore_bind,
	.connect = trustcore_connect,
	.socketpair = sock_no_socketpair,
	.accept = trustcore_accept,
	.getname = trustcore_getname,
	.poll = trustcore_poll,
	.ioctl = trustcore_ioctl,
	.listen = trustcore_listen,
	.shutdown = trustcore_shutdown,
	.setsockopt = trustcore_setsockopt,
	.getsockopt = trustcore_getsockopt,
	.sendmsg = trustcore_sendmsg,
	.recvmsg = trustcore_recvmsg,
	.mmap = sock_no_mmap,
};
EXPORT_SYMBOL_GPL(trustcore_inet6_ops);

static int __init trustcore_sock_init(void)
{
	int rc = trustcore_net_register_inbound_handler(tc_handle_inbound);
	if (rc && rc != -EBUSY)
		return rc;
	rc = proto_register(&trustcore_proto, 1);
	if (rc)
		return rc;
#ifdef CONFIG_DEBUG_FS
	tc_sock_debugfs_dir = debugfs_create_dir("trustcore_sock", NULL);
	if (!IS_ERR_OR_NULL(tc_sock_debugfs_dir))
		debugfs_create_file("sock_stats", 0444, tc_sock_debugfs_dir, NULL,
				    &tc_debugfs_sock_fops);
#endif
	return 0;
}

static void __exit trustcore_sock_exit(void)
{
#ifdef CONFIG_DEBUG_FS
	debugfs_remove_recursive(tc_sock_debugfs_dir);
	tc_sock_debugfs_dir = NULL;
#endif
	trustcore_net_cgroup_clear();
	proto_unregister(&trustcore_proto);
}

module_init(trustcore_sock_init);
module_exit(trustcore_sock_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Trustcore TCP socket ops");
