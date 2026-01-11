#ifndef _UAPI_LINUX_TRUSTCORE_NET_H
#define _UAPI_LINUX_TRUSTCORE_NET_H

#include <linux/types.h>

#define TRUSTCORE_NET_VERSION 3u
#define TRUSTCORE_NET_MAX_PAYLOAD (256u * 1024u)
/* Version 2 adds listener_id in tc_net_desc; version 3 adds UDP descriptors. */

enum tc_net_desc_type {
	TC_NET_DESC_CONNECT = 1,
	TC_NET_DESC_CONNECT_RESP = 2,
	TC_NET_DESC_LISTEN = 3,
	TC_NET_DESC_LISTEN_RESP = 4,
	TC_NET_DESC_ACCEPT = 5,
	TC_NET_DESC_SEND = 6,
	TC_NET_DESC_RECV = 7,
	TC_NET_DESC_CLOSE = 8,
	TC_NET_DESC_POLL_HINT = 9,
	TC_NET_DESC_DGRAM_BIND = 10,
	TC_NET_DESC_DGRAM_BIND_RESP = 11,
	TC_NET_DESC_DGRAM_CONNECT = 12,
	TC_NET_DESC_DGRAM_CONNECT_RESP = 13,
	TC_NET_DESC_DGRAM_SEND = 14,
	TC_NET_DESC_DGRAM_RECV = 15,
};

/* Descriptor flags */
enum tc_net_desc_flags {
	/*
	 * Aux buffer begins with struct tc_net_origin, followed by a type-specific
	 * payload (e.g., sockaddr for CONNECT/LISTEN).
	 */
	TC_NET_DESC_F_ORIGIN = 1u << 0,
};

/*
 * Descriptor semantics (v3):
 * - Payloads are contiguous; no wrap. data_off/aux_off are only valid when the
 *   corresponding length is non-zero.
 * - stream_id: long-lived handle for a connection or listener.
 * - req_id: request/response correlation for CONNECT/LISTEN.
 * - listener_id: listener handle for ACCEPT (0 otherwise).
 *
 * Type-specific fields:
 * CONNECT: stream_id!=0, req_id!=0, listener_id=0, aux=origin+sockaddr.
 * CONNECT_RESP: req_id!=0, stream_id!=0 on success; aux optional local sockaddr.
 * LISTEN: stream_id!=0, req_id!=0, listener_id=0, credit=backlog,
 *         aux=origin+sockaddr.
 * LISTEN_RESP: req_id!=0, stream_id!=0 on success; aux optional local sockaddr.
 * ACCEPT: listener_id!=0, stream_id!=0, req_id=0; aux optional peer sockaddr.
 * SEND: stream_id!=0, data_len>0, aux_len=0.
 * RECV: stream_id!=0, data_len>0, aux_len=0.
 * CLOSE: stream_id!=0, status optional error.
 * POLL_HINT: reserved; fields unused.
 * DGRAM_BIND: stream_id!=0, req_id!=0, aux=origin+sockaddr(local).
 * DGRAM_BIND_RESP: req_id!=0, stream_id!=0 on success; aux optional local sockaddr.
 * DGRAM_CONNECT: stream_id!=0, req_id!=0, aux=origin+sockaddr(remote).
 * DGRAM_CONNECT_RESP: req_id!=0, stream_id!=0 on success; aux optional local sockaddr.
 * DGRAM_SEND: stream_id!=0, data_len>0, aux optional sockaddr(remote).
 * DGRAM_RECV: stream_id!=0, data_len>0, aux optional sockaddr(remote).
 *
 * Status semantics:
 * - For *_RESP: status is 0 or a positive errno value.
 * - For CLOSE: status is 0 or a positive errno value.
 * - For RECV/ACCEPT/SEND/LISTEN/CONNECT: status must be 0.
 *
 * Memory ordering: producer writes payload, then descriptor, then updates
 * desc_head with store-release semantics. Consumer reads desc_head with
 * load-acquire semantics before reading descriptors/payload, and updates
 * desc_tail/data_tail with store-release semantics. Userspace must apply
 * the same acquire/release rules when publishing or consuming ring indices.
 */
struct tc_net_origin {
	__u32 tgid;
	__u32 uid;
	__u32 gid;
	__u32 reserved;
};

struct tc_net_desc {
	__u32 type;
	__u32 flags;
	__u64 stream_id;
	__u64 req_id;
	__u64 listener_id;
	__u32 data_off;
	__u32 data_len;
	__u32 aux_off;
	__u32 aux_len;
	/* For TC_NET_DESC_LISTEN, credit carries backlog. */
	__u32 credit;
	__u32 status;
};

struct tc_net_ring_header {
	__u32 version;
	__u32 flags;
	__u32 desc_count;
	__u32 header_size;
	__u32 desc_off;
	__u32 data_off;
	__u32 data_size;
	__u32 max_payload;
	__u32 desc_head;
	__u32 desc_tail;
	__u32 data_head;
	__u32 data_tail;
	__u32 reserved[4];
};

struct tc_net_version {
	__u32 version;
	__u32 flags;
	__u32 max_payload;
	__u32 reserved;
};

struct tc_net_config {
	__u32 version;
	__u32 flags;
	__u32 out_desc_count;
	__u32 in_desc_count;
	__u32 out_data_size;
	__u32 in_data_size;
	__u32 max_payload;
	__u32 reserved;
};

struct tc_net_layout {
	__u32 out_size;
	__u32 in_size;
	__u32 out_offset;
	__u32 in_offset;
	__u32 header_size;
	__u32 desc_size;
	__u32 flags;
	__u32 reserved;
};

struct tc_net_eventfds {
	__s32 out_eventfd;
	__s32 in_eventfd;
	__u32 reserved;
};

enum tc_net_cgroup_op {
	TC_NET_CGROUP_ADD = 1,
	TC_NET_CGROUP_DEL = 2,
	TC_NET_CGROUP_CLEAR = 3,
};

struct tc_net_cgroup_req {
	__u32 op;
	__u32 flags;
	__s32 fd;
	__u32 reserved;
	__u64 cgroup_id;
};

#define TC_NET_IOC_MAGIC 'T'

#define TC_NET_IOC_VERSION _IOWR(TC_NET_IOC_MAGIC, 0x00, struct tc_net_version)
#define TC_NET_IOC_CONFIG  _IOWR(TC_NET_IOC_MAGIC, 0x01, struct tc_net_config)
#define TC_NET_IOC_LAYOUT  _IOR(TC_NET_IOC_MAGIC, 0x02, struct tc_net_layout)
#define TC_NET_IOC_EVENTFD _IOW(TC_NET_IOC_MAGIC, 0x03, struct tc_net_eventfds)
#define TC_NET_IOC_KICK    _IO(TC_NET_IOC_MAGIC, 0x04)
#define TC_NET_IOC_CGROUP  _IOWR(TC_NET_IOC_MAGIC, 0x05, struct tc_net_cgroup_req)

#endif /* _UAPI_LINUX_TRUSTCORE_NET_H */
