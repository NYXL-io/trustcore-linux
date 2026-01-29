#include <linux/atomic.h>
#include <linux/eventfd.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/poll.h>
#include <linux/printk.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/vmalloc.h>

#include "trustcore_internal.h"

struct tc_ring {
	void *mem;
	size_t size;
	struct tc_net_ring_header *hdr;
	struct tc_net_desc *desc;
	u8 *data;
	spinlock_t lock;
	wait_queue_head_t wait;
};

struct tc_ctx {
	struct mutex lock;
	struct tc_ring ring_out;
	struct tc_ring ring_in;
	struct eventfd_ctx *out_eventfd;
	struct eventfd_ctx *in_eventfd;
	struct task_struct *rx_thread;
	bool configured;
	bool open;
};

static struct tc_ctx tc_ctx;
static tc_net_inbound_fn tc_inbound_handler;
static atomic64_t tc_in_bad_desc = ATOMIC64_INIT(0);
static atomic64_t tc_in_bad_bounds = ATOMIC64_INIT(0);
static atomic64_t tc_in_unknown_type = ATOMIC64_INIT(0);

#ifdef CONFIG_DEBUG_FS
static struct dentry *tc_debugfs_dir;

static int tc_debugfs_net_show(struct seq_file *s, void *unused)
{
	seq_printf(s, "in_bad_desc %lld\n", atomic64_read(&tc_in_bad_desc));
	seq_printf(s, "in_bad_bounds %lld\n", atomic64_read(&tc_in_bad_bounds));
	seq_printf(s, "in_unknown_type %lld\n", atomic64_read(&tc_in_unknown_type));
	return 0;
}

static int tc_debugfs_net_open(struct inode *inode, struct file *file)
{
	return single_open(file, tc_debugfs_net_show, NULL);
}

static const struct file_operations tc_debugfs_net_fops = {
	.owner = THIS_MODULE,
	.open = tc_debugfs_net_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

static unsigned int tc_out_desc_count = 4096;
static unsigned int tc_in_desc_count = 4096;
static unsigned int tc_out_data_size = 16 * 1024 * 1024;
static unsigned int tc_in_data_size = 16 * 1024 * 1024;
static unsigned int tc_max_payload = 64 * 1024;

module_param(tc_out_desc_count, uint, 0644);
module_param(tc_in_desc_count, uint, 0644);
module_param(tc_out_data_size, uint, 0644);
module_param(tc_in_data_size, uint, 0644);
module_param(tc_max_payload, uint, 0644);

static u32 tc_ring_header_size(void)
{
	return ALIGN(sizeof(struct tc_net_ring_header), 64);
}

static int tc_ring_init(struct tc_ring *ring,
			u32 desc_count,
			u32 data_size,
			u32 max_payload)
{
	u32 header_size = tc_ring_header_size();
	u32 desc_bytes = desc_count * sizeof(struct tc_net_desc);
	u32 data_off = ALIGN(header_size + desc_bytes, 64);
	size_t size = PAGE_ALIGN((size_t)data_off + data_size);
	void *mem;

	if (desc_count < 2 || data_size < max_payload) {
		return -EINVAL;
	}

	/* Use vmalloc_user so remap_vmalloc_range can map rings to userspace. */
	mem = vmalloc_user(size);
	if (!mem)
		return -ENOMEM;

	ring->mem = mem;
	ring->size = size;
	ring->hdr = mem;
	ring->desc = (struct tc_net_desc *)((u8 *)mem + header_size);
	ring->data = (u8 *)mem + data_off;
	spin_lock_init(&ring->lock);
	init_waitqueue_head(&ring->wait);

	ring->hdr->version = TRUSTCORE_NET_VERSION;
	ring->hdr->flags = 0;
	ring->hdr->desc_count = desc_count;
	ring->hdr->header_size = header_size;
	ring->hdr->desc_off = header_size;
	ring->hdr->data_off = data_off;
	ring->hdr->data_size = data_size;
	ring->hdr->max_payload = max_payload;
	ring->hdr->desc_head = 0;
	ring->hdr->desc_tail = 0;
	ring->hdr->data_head = 0;
	ring->hdr->data_tail = 0;
	return 0;
}

static void tc_ring_free(struct tc_ring *ring)
{
	if (!ring->mem)
		return;
	vfree(ring->mem);
	ring->mem = NULL;
	ring->size = 0;
	ring->hdr = NULL;
	ring->desc = NULL;
	ring->data = NULL;
}

static bool tc_ring_has_desc(const struct tc_ring *ring)
{
	u32 head = READ_ONCE(ring->hdr->desc_head);
	u32 tail = READ_ONCE(ring->hdr->desc_tail);

	return head != tail;
}

static bool tc_ring_has_desc_slot(const struct tc_ring *ring)
{
	u32 head = READ_ONCE(ring->hdr->desc_head);
	u32 tail = READ_ONCE(ring->hdr->desc_tail);
	u32 next = (head + 1) % ring->hdr->desc_count;

	return next != tail;
}

static bool tc_ring_has_space(const struct tc_ring *ring, u32 needed)
{
	u32 desc_head = READ_ONCE(ring->hdr->desc_head);
	u32 desc_tail = READ_ONCE(ring->hdr->desc_tail);
	u32 next = (desc_head + 1) % ring->hdr->desc_count;
	u32 data_head = READ_ONCE(ring->hdr->data_head);
	u32 data_tail = READ_ONCE(ring->hdr->data_tail);
	u32 data_size = ring->hdr->data_size;

	if (next == desc_tail)
		return false;

	if (needed > data_size)
		return false;

	if (data_head >= data_tail) {
		u32 free_space = data_size - (data_head - data_tail) - 1;
		if (needed > free_space)
			return false;
		if (data_head + needed > data_size && data_tail <= needed)
			return false;
		return true;
	}

	if (needed > (data_tail - data_head - 1))
		return false;

	return true;
}

static int tc_ring_try_push(struct tc_ring *ring,
			    struct tc_net_desc *desc,
			    const void *data,
			    u32 data_len,
			    const void *aux,
			    u32 aux_len)
{
	u32 desc_head;
	u32 desc_tail;
	u32 next;
	u32 data_head;
	u32 data_tail;
	u32 data_size;
	u32 needed;
	u32 data_off;
	u32 aux_off;
	u32 new_data_head;

	if (!ring->hdr)
		return -ENODEV;

	desc_head = READ_ONCE(ring->hdr->desc_head);
	desc_tail = READ_ONCE(ring->hdr->desc_tail);
	next = (desc_head + 1) % ring->hdr->desc_count;
	if (next == desc_tail)
		return -ENOSPC;

	needed = data_len + aux_len;
	if (needed > ring->hdr->data_size)
		return -EMSGSIZE;

	data_head = READ_ONCE(ring->hdr->data_head);
	data_tail = READ_ONCE(ring->hdr->data_tail);
	data_size = ring->hdr->data_size;

	if (data_head >= data_tail) {
		u32 free_space = data_size - (data_head - data_tail) - 1;
		if (needed > free_space)
			return -ENOSPC;
		if (data_head + needed > data_size) {
			if (data_tail <= needed)
				return -ENOSPC;
			data_off = 0;
			new_data_head = needed;
		} else {
			data_off = data_head;
			new_data_head = data_head + needed;
		}
	} else {
		u32 free_space = data_tail - data_head - 1;
		if (needed > free_space)
			return -ENOSPC;
		data_off = data_head;
		new_data_head = data_head + needed;
	}

	aux_off = data_off + data_len;

	if (data_len) {
		memcpy(ring->data + data_off, data, data_len);
	}
	if (aux_len) {
		memcpy(ring->data + aux_off, aux, aux_len);
	}

	desc->data_off = data_off;
	desc->data_len = data_len;
	desc->aux_off = aux_off;
	desc->aux_len = aux_len;

	ring->desc[desc_head] = *desc;
	smp_store_release(&ring->hdr->data_head, new_data_head % data_size);
	smp_store_release(&ring->hdr->desc_head, next);
	return 0;
}

static int tc_ring_try_push_iter(struct tc_ring *ring,
				 struct tc_net_desc *desc,
				 struct iov_iter *iter,
				 u32 data_len,
				 const void *aux,
				 u32 aux_len)
{
	u32 desc_head;
	u32 desc_tail;
	u32 next;
	u32 data_head;
	u32 data_tail;
	u32 data_size;
	u32 needed;
	u32 data_off;
	u32 aux_off;
	u32 new_data_head;

	if (!ring->hdr)
		return -ENODEV;

	desc_head = READ_ONCE(ring->hdr->desc_head);
	desc_tail = READ_ONCE(ring->hdr->desc_tail);
	next = (desc_head + 1) % ring->hdr->desc_count;
	if (next == desc_tail)
		return -ENOSPC;

	needed = data_len + aux_len;
	if (needed > ring->hdr->data_size)
		return -EMSGSIZE;

	data_head = READ_ONCE(ring->hdr->data_head);
	data_tail = READ_ONCE(ring->hdr->data_tail);
	data_size = ring->hdr->data_size;

	if (data_head >= data_tail) {
		u32 free_space = data_size - (data_head - data_tail) - 1;
		if (needed > free_space)
			return -ENOSPC;
		if (data_head + needed > data_size) {
			if (data_tail <= needed)
				return -ENOSPC;
			data_off = 0;
			new_data_head = needed;
		} else {
			data_off = data_head;
			new_data_head = data_head + needed;
		}
	} else {
		u32 free_space = data_tail - data_head - 1;
		if (needed > free_space)
			return -ENOSPC;
		data_off = data_head;
		new_data_head = data_head + needed;
	}

	aux_off = data_off + data_len;

	if (data_len) {
		struct iov_iter_state st;

		iov_iter_save_state(iter, &st);
		if (copy_from_iter(ring->data + data_off, data_len, iter) != data_len) {
			iov_iter_restore(iter, &st);
			return -EFAULT;
		}
	}
	if (aux_len)
		memcpy(ring->data + aux_off, aux, aux_len);

	desc->data_off = data_off;
	desc->data_len = data_len;
	desc->aux_off = aux_off;
	desc->aux_len = aux_len;

	ring->desc[desc_head] = *desc;
	smp_store_release(&ring->hdr->data_head, new_data_head % data_size);
	smp_store_release(&ring->hdr->desc_head, next);
	return 0;
}

static int tc_ring_push(struct tc_ring *ring,
			struct tc_net_desc *desc,
			const void *data,
			u32 data_len,
			const void *aux,
			u32 aux_len,
			bool nonblock)
{
	int rc;
	u32 needed = data_len + aux_len;

	for (;;) {
		spin_lock(&ring->lock);
		rc = tc_ring_try_push(ring, desc, data, data_len, aux, aux_len);
		spin_unlock(&ring->lock);
		if (rc == -ENOSPC && !nonblock) {
			wait_event_interruptible(ring->wait,
						 tc_ring_has_space(ring, needed) ||
						 !trustcore_net_ready());
			if (!trustcore_net_ready())
				return -ENETDOWN;
			continue;
		}
		return rc;
	}
}

static bool tc_ring_pop(struct tc_ring *ring, struct tc_net_desc *out_desc)
{
	u32 head;
	u32 tail;
	u32 next;
	u32 data_tail;
	u32 data_size;
	u32 advance;

	head = smp_load_acquire(&ring->hdr->desc_head);
	tail = READ_ONCE(ring->hdr->desc_tail);
	if (head == tail)
		return false;

	*out_desc = ring->desc[tail];
	next = (tail + 1) % ring->hdr->desc_count;

	advance = out_desc->data_len + out_desc->aux_len;
	data_tail = READ_ONCE(ring->hdr->data_tail);
	data_size = ring->hdr->data_size;
	if (advance) {
		data_tail = out_desc->data_off + advance;
		if (data_tail >= data_size)
			data_tail -= data_size;
		smp_store_release(&ring->hdr->data_tail, data_tail);
	}

	smp_store_release(&ring->hdr->desc_tail, next);
	return true;
}

static bool tc_aux_sockaddr_valid(const struct tc_ring *ring,
				  const struct tc_net_desc *d)
{
	if (!d->aux_len)
		return true;

	if (d->aux_len == sizeof(struct sockaddr_in)) {
		struct sockaddr_in sin;

		memcpy(&sin, ring->data + d->aux_off, sizeof(sin));
		return sin.sin_family == AF_INET;
	}
	if (d->aux_len == sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 sin6;

		memcpy(&sin6, ring->data + d->aux_off, sizeof(sin6));
		return sin6.sin6_family == AF_INET6;
	}

	return false;
}

static bool tc_desc_validate_in(const struct tc_ring *ring,
				const struct tc_net_desc *d)
{
	u32 data_size = ring->hdr->data_size;
	u32 total;
	u32 end;

	switch (d->type) {
	case TC_NET_DESC_CONNECT_RESP:
	case TC_NET_DESC_LISTEN_RESP:
	case TC_NET_DESC_ACCEPT:
	case TC_NET_DESC_RECV:
	case TC_NET_DESC_CLOSE:
	case TC_NET_DESC_DGRAM_BIND_RESP:
	case TC_NET_DESC_DGRAM_CONNECT_RESP:
	case TC_NET_DESC_DGRAM_RECV:
		break;
	default:
		atomic64_inc(&tc_in_unknown_type);
		return false;
	}

	if (d->flags) {
		atomic64_inc(&tc_in_bad_desc);
		return false;
	}

	if (check_add_overflow(d->data_len, d->aux_len, &total) ||
	    total > data_size) {
		atomic64_inc(&tc_in_bad_bounds);
		return false;
	}

	if (d->data_len) {
		if (d->data_off >= data_size) {
			atomic64_inc(&tc_in_bad_bounds);
			return false;
		}
		if (check_add_overflow(d->data_off, d->data_len, &end) ||
		    end > data_size) {
			atomic64_inc(&tc_in_bad_bounds);
			return false;
		}
	}

	if (d->aux_len) {
		if (d->aux_off >= data_size) {
			atomic64_inc(&tc_in_bad_bounds);
			return false;
		}
		if (check_add_overflow(d->aux_off, d->aux_len, &end) ||
		    end > data_size) {
			atomic64_inc(&tc_in_bad_bounds);
			return false;
		}
	}

	switch (d->type) {
	case TC_NET_DESC_RECV:
		if (!d->stream_id || d->req_id || d->listener_id ||
		    !d->data_len || d->data_len > ring->hdr->max_payload ||
		    d->aux_len || d->status) {
			atomic64_inc(&tc_in_bad_desc);
			return false;
		}
		break;
	case TC_NET_DESC_CONNECT_RESP:
	case TC_NET_DESC_LISTEN_RESP:
	case TC_NET_DESC_DGRAM_BIND_RESP:
	case TC_NET_DESC_DGRAM_CONNECT_RESP:
		if (!d->req_id || d->listener_id || d->data_len ||
		    d->status > MAX_ERRNO) {
			atomic64_inc(&tc_in_bad_desc);
			return false;
		}
		if (!d->status && !d->stream_id) {
			atomic64_inc(&tc_in_bad_desc);
			return false;
		}
		if (!tc_aux_sockaddr_valid(ring, d)) {
			atomic64_inc(&tc_in_bad_desc);
			return false;
		}
		break;
	case TC_NET_DESC_ACCEPT:
		if (d->req_id || !d->listener_id || !d->stream_id || d->data_len ||
		    d->status) {
			atomic64_inc(&tc_in_bad_desc);
			return false;
		}
		if (!tc_aux_sockaddr_valid(ring, d)) {
			atomic64_inc(&tc_in_bad_desc);
			return false;
		}
		break;
	case TC_NET_DESC_DGRAM_RECV:
		if (!d->stream_id || d->req_id || d->listener_id ||
		    !d->data_len || d->data_len > ring->hdr->max_payload ||
		    d->status) {
			atomic64_inc(&tc_in_bad_desc);
			return false;
		}
		if (!tc_aux_sockaddr_valid(ring, d)) {
			atomic64_inc(&tc_in_bad_desc);
			return false;
		}
		break;
	case TC_NET_DESC_CLOSE:
		if (!d->stream_id || d->req_id || d->listener_id ||
		    d->data_len || d->aux_len || d->status > MAX_ERRNO) {
			atomic64_inc(&tc_in_bad_desc);
			return false;
		}
		break;
	default:
		break;
	}

	return true;
}

bool trustcore_net_ready(void)
{
	return READ_ONCE(tc_ctx.configured);
}
EXPORT_SYMBOL_GPL(trustcore_net_ready);

u32 trustcore_net_max_payload(void)
{
	if (!tc_ctx.configured || !tc_ctx.ring_out.hdr)
		return 0;
	return tc_ctx.ring_out.hdr->max_payload;
}

bool trustcore_net_tx_ready(u32 needed)
{
	if (!tc_ctx.configured || !tc_ctx.ring_out.hdr)
		return false;
	/*
	 * Lockless: tc_ring_has_space reads head/tail with READ_ONCE.
	 * This is a readiness hint for poll/epoll to avoid busy loops.
	 */
	return tc_ring_has_space(&tc_ctx.ring_out, needed);
}
EXPORT_SYMBOL_GPL(trustcore_net_tx_ready);

int trustcore_net_register_inbound_handler(tc_net_inbound_fn handler)
{
	if (tc_inbound_handler)
		return -EBUSY;
	tc_inbound_handler = handler;
	return 0;
}

int trustcore_net_send_desc(struct tc_net_desc *desc,
			    const void *data,
			    u32 data_len,
			    const void *aux,
			    u32 aux_len,
			    bool nonblock)
{
	int rc;

	if (!trustcore_net_ready()) {
		return -ENETDOWN;
	}

	rc = tc_ring_push(&tc_ctx.ring_out, desc, data, data_len, aux, aux_len, nonblock);
	if (rc) {
		return rc;
	}

	wake_up_interruptible(&tc_ctx.ring_out.wait);
	if (tc_ctx.out_eventfd)
		eventfd_signal(tc_ctx.out_eventfd);
	return 0;
}

int trustcore_net_send_desc_iter(struct tc_net_desc *desc,
				 struct iov_iter *iter,
				 u32 data_len,
				 const void *aux,
				 u32 aux_len,
				 bool nonblock)
{
	int rc;
	u32 needed = data_len + aux_len;

	if (!trustcore_net_ready()) {
		return -ENETDOWN;
	}

	for (;;) {
		spin_lock(&tc_ctx.ring_out.lock);
		rc = tc_ring_try_push_iter(&tc_ctx.ring_out, desc, iter, data_len,
					   aux, aux_len);
		spin_unlock(&tc_ctx.ring_out.lock);
		if (rc == -ENOSPC && !nonblock) {
			wait_event_interruptible(tc_ctx.ring_out.wait,
						 tc_ring_has_space(&tc_ctx.ring_out, needed) ||
						 !trustcore_net_ready());
			if (!trustcore_net_ready())
				return -ENETDOWN;
			continue;
		}
		if (rc) {
			return rc;
		}
		break;
	}

	wake_up_interruptible(&tc_ctx.ring_out.wait);
	if (tc_ctx.out_eventfd)
		eventfd_signal(tc_ctx.out_eventfd);
	return 0;
}

static int tc_rx_thread(void *arg)
{
	struct tc_net_desc desc;

	while (!kthread_should_stop()) {
		wait_event_interruptible(tc_ctx.ring_in.wait,
					 tc_ring_has_desc(&tc_ctx.ring_in) ||
					 kthread_should_stop());
		if (kthread_should_stop())
			break;

		while (tc_ring_has_desc(&tc_ctx.ring_in)) {
			void *data_buf = NULL;
			void *aux_buf = NULL;
			if (!tc_ring_pop(&tc_ctx.ring_in, &desc))
				break;
			if (!tc_desc_validate_in(&tc_ctx.ring_in, &desc)) {
				pr_debug_ratelimited("trustcore-net: drop invalid inbound desc type=%u\n",
						     desc.type);
				if (tc_ctx.in_eventfd)
					eventfd_signal(tc_ctx.in_eventfd);
				continue;
			}

			if (desc.type == TC_NET_DESC_RECV) {
				if (desc.data_len) {
					int rc;
					pr_info("trustcore-net: inbound RECV stream_id=%llu len=%u\n",
						desc.stream_id, desc.data_len);
					rc = trustcore_sock_deliver_recv(desc.stream_id,
								    tc_ctx.ring_in.data + desc.data_off,
								    desc.data_len);
					if (rc)
						pr_info("trustcore-net: deliver recv failed stream_id=%llu rc=%d\n",
							desc.stream_id, rc);
				}
				if (tc_ctx.in_eventfd)
					eventfd_signal(tc_ctx.in_eventfd);
				continue;
			}
			if (desc.type == TC_NET_DESC_DGRAM_RECV) {
				if (desc.data_len) {
					int rc;
					pr_info("trustcore-net: inbound DGRAM_RECV stream_id=%llu len=%u aux_len=%u\n",
						desc.stream_id, desc.data_len, desc.aux_len);
					rc = trustcore_sock_deliver_recv_from(desc.stream_id,
									 tc_ctx.ring_in.data + desc.data_off,
									 desc.data_len,
									 desc.aux_len ? tc_ctx.ring_in.data + desc.aux_off : NULL,
									 desc.aux_len);
					if (rc)
						pr_info("trustcore-net: deliver dgram recv failed stream_id=%llu rc=%d\n",
							desc.stream_id, rc);
				}
				if (tc_ctx.in_eventfd)
					eventfd_signal(tc_ctx.in_eventfd);
				continue;
			}

			if (desc.data_len) {
				data_buf = kmalloc(desc.data_len, GFP_KERNEL);
				if (data_buf)
					memcpy(data_buf, tc_ctx.ring_in.data + desc.data_off, desc.data_len);
			}

			if (desc.aux_len) {
				aux_buf = kmalloc(desc.aux_len, GFP_KERNEL);
				if (aux_buf)
					memcpy(aux_buf, tc_ctx.ring_in.data + desc.aux_off, desc.aux_len);
			}

			if (tc_inbound_handler) {
				tc_inbound_handler(&desc, data_buf, desc.data_len, aux_buf, desc.aux_len);
			} else {
				kfree(data_buf);
				kfree(aux_buf);
			}

			if (tc_ctx.in_eventfd)
				eventfd_signal(tc_ctx.in_eventfd);
		}
	}

	return 0;
}

static int tc_device_open(struct inode *inode, struct file *file)
{
	/* Only trusted control plane should own the device */
	if (!ns_capable(&init_user_ns, CAP_NET_ADMIN))
		return -EPERM;

	mutex_lock(&tc_ctx.lock);
	if (tc_ctx.open) {
		mutex_unlock(&tc_ctx.lock);
		return -EBUSY;
	}
	tc_ctx.open = true;
	mutex_unlock(&tc_ctx.lock);
	return 0;
}

static int tc_device_release(struct inode *inode, struct file *file)
{
	mutex_lock(&tc_ctx.lock);
	tc_ctx.open = false;
	WRITE_ONCE(tc_ctx.configured, false);
	{
		struct tc_net_intercept_req req = {
			.mode = TC_NET_INTERCEPT_OFF,
			.uid = -1,
			.gid = -1,
			.flags = 0,
		};
		trustcore_net_set_intercept(&req);
		trustcore_net_cgroup_clear();
	}
	wake_up_all(&tc_ctx.ring_out.wait);
	wake_up_all(&tc_ctx.ring_in.wait);
	trustcore_sock_abort_all(ENETDOWN);
	if (tc_ctx.rx_thread) {
		kthread_stop(tc_ctx.rx_thread);
		tc_ctx.rx_thread = NULL;
	}
	if (tc_ctx.out_eventfd) {
		eventfd_ctx_put(tc_ctx.out_eventfd);
		tc_ctx.out_eventfd = NULL;
	}
	if (tc_ctx.in_eventfd) {
		eventfd_ctx_put(tc_ctx.in_eventfd);
		tc_ctx.in_eventfd = NULL;
	}
	tc_ring_free(&tc_ctx.ring_out);
	tc_ring_free(&tc_ctx.ring_in);
	mutex_unlock(&tc_ctx.lock);
	return 0;
}

static long tc_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct tc_net_version ver;
	struct tc_net_config cfg;
	struct tc_net_layout layout;
	struct tc_net_eventfds ev;
	struct tc_net_cgroup_req cg;
	struct tc_net_intercept_req ic;
	int rc = 0;

	mutex_lock(&tc_ctx.lock);
	switch (cmd) {
	case TC_NET_IOC_VERSION:
		if (copy_from_user(&ver, (void __user *)arg, sizeof(ver))) {
			rc = -EFAULT;
			break;
		}
		if (ver.version != TRUSTCORE_NET_VERSION) {
			rc = -EPROTONOSUPPORT;
			break;
		}
		ver.max_payload = min(tc_max_payload, (unsigned int)TRUSTCORE_NET_MAX_PAYLOAD);
		if (copy_to_user((void __user *)arg, &ver, sizeof(ver)))
			rc = -EFAULT;
		break;
	case TC_NET_IOC_CONFIG:
		if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg))) {
			rc = -EFAULT;
			break;
		}
		if (tc_ctx.configured) {
			rc = -EBUSY;
			break;
		}
		if (cfg.version != TRUSTCORE_NET_VERSION) {
			rc = -EPROTONOSUPPORT;
			break;
		}
		if (cfg.out_desc_count == 0)
			cfg.out_desc_count = tc_out_desc_count;
		if (cfg.in_desc_count == 0)
			cfg.in_desc_count = tc_in_desc_count;
		if (cfg.out_data_size == 0)
			cfg.out_data_size = tc_out_data_size;
		if (cfg.in_data_size == 0)
			cfg.in_data_size = tc_in_data_size;
		if (cfg.max_payload == 0 || cfg.max_payload > TRUSTCORE_NET_MAX_PAYLOAD)
			cfg.max_payload = min(tc_max_payload, (unsigned int)TRUSTCORE_NET_MAX_PAYLOAD);

		rc = tc_ring_init(&tc_ctx.ring_out, cfg.out_desc_count, cfg.out_data_size, cfg.max_payload);
		if (rc)
			break;
		rc = tc_ring_init(&tc_ctx.ring_in, cfg.in_desc_count, cfg.in_data_size, cfg.max_payload);
		if (rc) {
			tc_ring_free(&tc_ctx.ring_out);
			break;
		}
		tc_ctx.configured = true;
		if (!tc_ctx.rx_thread) {
			tc_ctx.rx_thread = kthread_run(tc_rx_thread, NULL, "trustcore-net");
			if (IS_ERR(tc_ctx.rx_thread)) {
				rc = PTR_ERR(tc_ctx.rx_thread);
				tc_ctx.rx_thread = NULL;
				tc_ctx.configured = false;
				tc_ring_free(&tc_ctx.ring_out);
				tc_ring_free(&tc_ctx.ring_in);
				break;
			}
		}

		if (copy_to_user((void __user *)arg, &cfg, sizeof(cfg)))
			rc = -EFAULT;
		break;
	case TC_NET_IOC_LAYOUT:
		if (!tc_ctx.configured) {
			rc = -ENODEV;
			break;
		}
		layout.out_size = tc_ctx.ring_out.size;
		layout.in_size = tc_ctx.ring_in.size;
		layout.out_offset = 0;
		layout.in_offset = tc_ctx.ring_out.size;
		layout.header_size = tc_ring_header_size();
		layout.desc_size = sizeof(struct tc_net_desc);
		layout.flags = 0;
		if (copy_to_user((void __user *)arg, &layout, sizeof(layout)))
			rc = -EFAULT;
		break;
	case TC_NET_IOC_EVENTFD:
		if (copy_from_user(&ev, (void __user *)arg, sizeof(ev))) {
			rc = -EFAULT;
			break;
		}
		if (tc_ctx.out_eventfd)
			eventfd_ctx_put(tc_ctx.out_eventfd);
		if (tc_ctx.in_eventfd)
			eventfd_ctx_put(tc_ctx.in_eventfd);
		tc_ctx.out_eventfd = eventfd_ctx_fdget(ev.out_eventfd);
		if (IS_ERR(tc_ctx.out_eventfd)) {
			rc = PTR_ERR(tc_ctx.out_eventfd);
			tc_ctx.out_eventfd = NULL;
			break;
		}
		tc_ctx.in_eventfd = eventfd_ctx_fdget(ev.in_eventfd);
		if (IS_ERR(tc_ctx.in_eventfd)) {
			rc = PTR_ERR(tc_ctx.in_eventfd);
			eventfd_ctx_put(tc_ctx.out_eventfd);
			tc_ctx.out_eventfd = NULL;
			tc_ctx.in_eventfd = NULL;
			break;
		}
		break;
	case TC_NET_IOC_KICK:
		wake_up_interruptible(&tc_ctx.ring_in.wait);
		wake_up_interruptible(&tc_ctx.ring_out.wait);
		break;
	case TC_NET_IOC_CGROUP:
		if (copy_from_user(&cg, (void __user *)arg, sizeof(cg))) {
			rc = -EFAULT;
			break;
		}
		switch (cg.op) {
		case TC_NET_CGROUP_ADD:
			rc = trustcore_net_cgroup_add(cg.fd, &cg.cgroup_id);
			break;
		case TC_NET_CGROUP_DEL:
			rc = trustcore_net_cgroup_del(cg.cgroup_id);
			break;
		case TC_NET_CGROUP_CLEAR:
			trustcore_net_cgroup_clear();
			rc = 0;
			break;
		default:
			rc = -EINVAL;
			break;
		}
		if (!rc && copy_to_user((void __user *)arg, &cg, sizeof(cg)))
			rc = -EFAULT;
		break;
	case TC_NET_IOC_INTERCEPT:
		if (copy_from_user(&ic, (void __user *)arg, sizeof(ic))) {
			rc = -EFAULT;
			break;
		}
		if (ic.flags & TC_NET_INTERCEPT_F_QUERY) {
			trustcore_net_get_intercept(&ic);
			rc = 0;
		} else {
			rc = trustcore_net_set_intercept(&ic);
			if (!rc)
				trustcore_net_get_intercept(&ic);
		}
		if (!rc && copy_to_user((void __user *)arg, &ic, sizeof(ic)))
			rc = -EFAULT;
		break;
	default:
		rc = -ENOIOCTLCMD;
		break;
	}
	mutex_unlock(&tc_ctx.lock);
	return rc;
}

static int tc_device_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long len = vma->vm_end - vma->vm_start;
	void *mem = NULL;
	size_t size = 0;

	mutex_lock(&tc_ctx.lock);
	if (!tc_ctx.configured) {
		mutex_unlock(&tc_ctx.lock);
		return -ENODEV;
	}

	if (vma->vm_flags & VM_EXEC) {
		mutex_unlock(&tc_ctx.lock);
		return -EPERM;
	}
	if (!(vma->vm_flags & VM_SHARED)) {
		mutex_unlock(&tc_ctx.lock);
		return -EINVAL;
	}

	if (offset == 0) {
		mem = tc_ctx.ring_out.mem;
		size = tc_ctx.ring_out.size;
	} else if (offset == tc_ctx.ring_out.size) {
		mem = tc_ctx.ring_in.mem;
		size = tc_ctx.ring_in.size;
	}

	if (!mem || len != size) {
		mutex_unlock(&tc_ctx.lock);
		return -EINVAL;
	}

	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
	if (remap_vmalloc_range(vma, mem, 0)) {
		mutex_unlock(&tc_ctx.lock);
		return -EAGAIN;
	}

	mutex_unlock(&tc_ctx.lock);
	return 0;
}

static __poll_t tc_device_poll(struct file *file, poll_table *wait)
{
	__poll_t mask = 0;

	poll_wait(file, &tc_ctx.ring_out.wait, wait);
	poll_wait(file, &tc_ctx.ring_in.wait, wait);

	/*
	 * Userspace reads kernel->userspace descriptors from ring_out.
	 */
	if (tc_ring_has_desc(&tc_ctx.ring_out))
		mask |= POLLIN | POLLRDNORM;
	/*
	 * Userspace writes userspace->kernel descriptors into ring_in.
	 * Advertise writability when there is at least one descriptor slot.
	 */
	if (tc_ctx.configured && tc_ctx.ring_in.hdr &&
	    tc_ring_has_desc_slot(&tc_ctx.ring_in))
		mask |= POLLOUT | POLLWRNORM;
	if (!trustcore_net_ready())
		mask |= POLLERR | POLLHUP;
	return mask;
}

static ssize_t tc_device_write(struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
	wake_up_interruptible(&tc_ctx.ring_in.wait);
	wake_up_interruptible(&tc_ctx.ring_out.wait);
	return len ? (ssize_t)len : 0;
}

static const struct file_operations tc_device_fops = {
	.owner = THIS_MODULE,
	.open = tc_device_open,
	.release = tc_device_release,
	.unlocked_ioctl = tc_device_ioctl,
	.mmap = tc_device_mmap,
	.poll = tc_device_poll,
	.write = tc_device_write,
};

static struct miscdevice tc_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "trustcore-net",
	.fops = &tc_device_fops,
};

static int __init trustcore_net_init(void)
{
	int rc;

	mutex_init(&tc_ctx.lock);
	rc = misc_register(&tc_device);
	if (rc)
		return rc;
#ifdef CONFIG_DEBUG_FS
	tc_debugfs_dir = debugfs_create_dir("trustcore_net", NULL);
	if (!IS_ERR_OR_NULL(tc_debugfs_dir))
		debugfs_create_file("net_stats", 0444, tc_debugfs_dir, NULL,
				    &tc_debugfs_net_fops);
#endif
	return 0;
}

static void __exit trustcore_net_exit(void)
{
#ifdef CONFIG_DEBUG_FS
	debugfs_remove_recursive(tc_debugfs_dir);
	tc_debugfs_dir = NULL;
#endif
	misc_deregister(&tc_device);
}

module_init(trustcore_net_init);
module_exit(trustcore_net_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Trustcore network device");
