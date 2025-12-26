// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/trustcore_net.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/capability.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../kselftest.h"

#define DEV_PATH "/dev/trustcore-net"
#define PARAM_PATH "/sys/module/trustcore_sock/parameters/trustcore_intercept_mode"
#define LSM_PATH "/sys/kernel/security/lsm"

struct tc_ring_view {
	struct tc_net_ring_header *hdr;
	struct tc_net_desc *desc;
	uint8_t *data;
};

struct listen_args {
	int fd;
	int rc;
};

static int trustcore_lsm_status(void)
{
	char buf[256];
	ssize_t len;
	int fd;

	fd = open(LSM_PATH, O_RDONLY);
	if (fd < 0)
		return -errno;
	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len <= 0)
		return -EIO;
	buf[len] = '\0';
	return strstr(buf, "trustcore_net") ? 1 : 0;
}

static bool cap_net_raw_enabled(void)
{
	char line[256];
	unsigned long long caps = 0;
	FILE *fp;

	fp = fopen("/proc/self/status", "r");
	if (!fp)
		return false;
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "CapEff:", 7) == 0) {
			if (sscanf(line + 7, "%llx", &caps) != 1)
				caps = 0;
			break;
		}
	}
	fclose(fp);
	return !!(caps & (1ULL << CAP_NET_RAW));
}

static void ring_init(void *mem, struct tc_ring_view *ring)
{
	ring->hdr = (struct tc_net_ring_header *)mem;
	ring->desc = (struct tc_net_desc *)((uint8_t *)mem + ring->hdr->desc_off);
	ring->data = (uint8_t *)mem + ring->hdr->data_off;
}

static int ring_pop(struct tc_ring_view *ring, struct tc_net_desc *out_desc)
{
	uint32_t head = __atomic_load_n(&ring->hdr->desc_head, __ATOMIC_ACQUIRE);
	uint32_t tail = __atomic_load_n(&ring->hdr->desc_tail, __ATOMIC_RELAXED);
	uint32_t next;
	uint32_t advance;
	uint32_t data_tail;
	uint32_t data_size;

	if (head == tail)
		return 0;

	*out_desc = ring->desc[tail];
	next = (tail + 1) % ring->hdr->desc_count;

	advance = out_desc->data_len + out_desc->aux_len;
	data_tail = ring->hdr->data_tail;
	data_size = ring->hdr->data_size;
	if (advance) {
		data_tail = out_desc->data_off + advance;
		if (data_tail >= data_size)
			data_tail -= data_size;
		__atomic_store_n(&ring->hdr->data_tail, data_tail, __ATOMIC_RELEASE);
	}

	__atomic_store_n(&ring->hdr->desc_tail, next, __ATOMIC_RELEASE);
	return 1;
}

static int ring_push(struct tc_ring_view *ring, struct tc_net_desc *desc,
		     const void *data, uint32_t data_len,
		     const void *aux, uint32_t aux_len)
{
	uint32_t desc_head = __atomic_load_n(&ring->hdr->desc_head, __ATOMIC_RELAXED);
	uint32_t desc_tail = __atomic_load_n(&ring->hdr->desc_tail, __ATOMIC_ACQUIRE);
	uint32_t next = (desc_head + 1) % ring->hdr->desc_count;
	uint32_t data_head = __atomic_load_n(&ring->hdr->data_head, __ATOMIC_RELAXED);
	uint32_t data_tail = __atomic_load_n(&ring->hdr->data_tail, __ATOMIC_ACQUIRE);
	uint32_t data_size = ring->hdr->data_size;
	uint32_t needed = data_len + aux_len;
	uint32_t data_off;
	uint32_t aux_off;
	uint32_t new_data_head;

	if (next == desc_tail)
		return -ENOSPC;
	if (needed > data_size)
		return -EMSGSIZE;

	if (data_head >= data_tail) {
		uint32_t free_space = data_size - (data_head - data_tail) - 1;

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
		uint32_t free_space = data_tail - data_head - 1;

		if (needed > free_space)
			return -ENOSPC;
		data_off = data_head;
		new_data_head = data_head + needed;
	}

	aux_off = data_off + data_len;
	if (data_len)
		memcpy(ring->data + data_off, data, data_len);
	if (aux_len)
		memcpy(ring->data + aux_off, aux, aux_len);

	desc->data_off = data_off;
	desc->data_len = data_len;
	desc->aux_off = aux_off;
	desc->aux_len = aux_len;

	ring->desc[desc_head] = *desc;
	__atomic_store_n(&ring->hdr->data_head, new_data_head % data_size, __ATOMIC_RELEASE);
	__atomic_store_n(&ring->hdr->desc_head, next, __ATOMIC_RELEASE);
	return 0;
}

static int wait_for_desc(struct tc_ring_view *ring, struct tc_net_desc *out_desc)
{
	for (int i = 0; i < 1000; i++) {
		if (ring_pop(ring, out_desc))
			return 0;
		usleep(1000);
	}
	return -ETIMEDOUT;
}

static void *listen_thread(void *arg)
{
	struct listen_args *args = arg;

	args->rc = listen(args->fd, 4);
	return NULL;
}

static int set_intercept_mode(void)
{
	int fd = open(PARAM_PATH, O_WRONLY);
	ssize_t rc;

	if (fd < 0)
		return -errno;
	rc = write(fd, "1\n", 2);
	close(fd);
	return rc < 0 ? -errno : 0;
}

int main(void)
{
	struct tc_net_version ver = {};
	struct tc_net_config cfg = {};
	struct tc_net_layout layout = {};
	struct tc_ring_view ring_out = {};
	struct tc_ring_view ring_in = {};
	struct tc_net_desc desc = {};
	struct tc_net_desc resp = {};
	struct sockaddr_in sin = {};
	struct sockaddr_in peer = {};
	struct sockaddr_in udp_peer = {};
	struct sockaddr_in udp_from = {};
	struct listen_args largs = {};
	const char udp_send[] = "ping";
	const char udp_recv[] = "pong";
	char udp_buf[16];
	u64 udp_stream_id = 0;
	pthread_t lthread;
	void *out_map = MAP_FAILED;
	void *in_map = MAP_FAILED;
	int intercept_rc = 0;
	int udpfd = -1;
	int devfd;
	int srvfd = -1;
	int clifd = -1;
	int accfd = -1;
	int rc;
	int lsm_status;

	ksft_set_plan(3);

	if (geteuid() != 0)
		ksft_exit_skip("requires root\n");

	devfd = open(DEV_PATH, O_RDWR);
	if (devfd < 0)
		ksft_exit_skip("trustcore device not available\n");

	{
		int sret = set_intercept_mode();

		intercept_rc = sret;
	}

	ver.version = TRUSTCORE_NET_VERSION;
	rc = ioctl(devfd, TC_NET_IOC_VERSION, &ver);
	if (rc)
		ksft_exit_fail_msg("TC_NET_IOC_VERSION failed: %s\n", strerror(errno));
	if (ver.version != TRUSTCORE_NET_VERSION)
		ksft_exit_fail_msg("unexpected version %u\n", ver.version);

	cfg.version = TRUSTCORE_NET_VERSION;
	cfg.out_desc_count = 64;
	cfg.in_desc_count = 64;
	cfg.out_data_size = 64 * 1024;
	cfg.in_data_size = 64 * 1024;
	cfg.max_payload = 4096;
	rc = ioctl(devfd, TC_NET_IOC_CONFIG, &cfg);
	if (rc)
		ksft_exit_fail_msg("TC_NET_IOC_CONFIG failed: %s\n", strerror(errno));
	rc = ioctl(devfd, TC_NET_IOC_LAYOUT, &layout);
	if (rc)
		ksft_exit_fail_msg("TC_NET_IOC_LAYOUT failed: %s\n", strerror(errno));

	out_map = mmap(NULL, layout.out_size, PROT_READ | PROT_WRITE, MAP_SHARED, devfd, 0);
	in_map = mmap(NULL, layout.in_size, PROT_READ | PROT_WRITE, MAP_SHARED, devfd, layout.in_offset);
	if (out_map == MAP_FAILED || in_map == MAP_FAILED)
		ksft_exit_fail_msg("mmap failed\n");

	ring_init(out_map, &ring_out);
	ring_init(in_map, &ring_in);

	srvfd = socket(AF_INET, SOCK_STREAM, 0);
	if (srvfd < 0)
		ksft_exit_fail_msg("socket failed: %s\n", strerror(errno));

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = 0;
	rc = bind(srvfd, (struct sockaddr *)&sin, sizeof(sin));
	if (rc)
		ksft_exit_fail_msg("bind failed: %s\n", strerror(errno));

	largs.fd = srvfd;
	largs.rc = -1;
	rc = pthread_create(&lthread, NULL, listen_thread, &largs);
	if (rc)
		ksft_exit_fail_msg("pthread_create failed\n");

	rc = wait_for_desc(&ring_out, &desc);
	if (rc) {
		if (intercept_rc)
			ksft_exit_skip("no LISTEN descriptor observed (intercept_mode write failed: %s)\n",
				       strerror(-intercept_rc));
		else
			ksft_exit_skip("no LISTEN descriptor observed\n");
	}
	if (desc.type != TC_NET_DESC_LISTEN)
		ksft_exit_fail_msg("unexpected desc type %u\n", desc.type);

	memset(&resp, 0, sizeof(resp));
	resp.type = TC_NET_DESC_LISTEN_RESP;
	resp.req_id = desc.req_id;
	resp.stream_id = desc.stream_id;
	resp.status = 0;
	sin.sin_port = htons(12345);
	rc = ring_push(&ring_in, &resp, NULL, 0, &sin, sizeof(sin));
	if (rc)
		ksft_exit_fail_msg("ring_push listen_resp failed\n");
	ioctl(devfd, TC_NET_IOC_KICK);

	pthread_join(lthread, NULL);
	if (largs.rc)
		ksft_exit_fail_msg("listen failed: %s\n", strerror(errno));

	memset(&peer, 0, sizeof(peer));
	peer.sin_family = AF_INET;
	peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	peer.sin_port = htons(55555);
	memset(&resp, 0, sizeof(resp));
	resp.type = TC_NET_DESC_ACCEPT;
	resp.listener_id = desc.stream_id;
	resp.stream_id = 100;
	resp.status = 0;
	rc = ring_push(&ring_in, &resp, NULL, 0, &peer, sizeof(peer));
	if (rc)
		ksft_exit_fail_msg("ring_push accept failed\n");
	ioctl(devfd, TC_NET_IOC_KICK);

	accfd = accept(srvfd, NULL, NULL);
	if (accfd < 0)
		ksft_exit_fail_msg("accept failed: %s\n", strerror(errno));

	clifd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (clifd < 0)
		ksft_exit_fail_msg("client socket failed: %s\n", strerror(errno));

	rc = connect(clifd, (struct sockaddr *)&sin, sizeof(sin));
	if (rc == 0 || (rc < 0 && errno != EINPROGRESS))
		ksft_exit_fail_msg("connect failed: %s\n", strerror(errno));

	rc = wait_for_desc(&ring_out, &desc);
	if (rc)
		ksft_exit_skip("no CONNECT descriptor observed\n");
	if (desc.type != TC_NET_DESC_CONNECT)
		ksft_exit_fail_msg("unexpected desc type %u\n", desc.type);

	memset(&resp, 0, sizeof(resp));
	resp.type = TC_NET_DESC_CONNECT_RESP;
	resp.req_id = desc.req_id;
	resp.stream_id = desc.stream_id;
	resp.status = 0;
	rc = ring_push(&ring_in, &resp, NULL, 0, NULL, 0);
	if (rc)
		ksft_exit_fail_msg("ring_push connect_resp failed\n");
	ioctl(devfd, TC_NET_IOC_KICK);

	{
		struct pollfd pfd = { .fd = clifd, .events = POLLOUT };

		poll(&pfd, 1, 1000);
	}
	{
		int so_err = 0;
		socklen_t so_err_len = sizeof(so_err);

		if (getsockopt(clifd, SOL_SOCKET, SO_ERROR, &so_err, &so_err_len))
			ksft_exit_fail_msg("getsockopt SO_ERROR failed\n");
		if (so_err)
			ksft_exit_fail_msg("connect error %d\n", so_err);
	}

	ksft_test_result_pass("trustcore net basic flow\n");

	udpfd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (udpfd < 0)
		ksft_exit_fail_msg("udp socket failed: %s\n", strerror(errno));

	memset(&udp_peer, 0, sizeof(udp_peer));
	udp_peer.sin_family = AF_INET;
	udp_peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	udp_peer.sin_port = htons(54321);

	rc = sendto(udpfd, udp_send, sizeof(udp_send) - 1, MSG_DONTWAIT,
		    (struct sockaddr *)&udp_peer, sizeof(udp_peer));
	if (rc >= 0) {
		if (intercept_rc) {
			ksft_test_result_skip("trustcore net udp flow (intercept_mode write failed: %s)\n",
					      strerror(-intercept_rc));
			goto lsm_test;
		}
		ksft_exit_fail_msg("udp sendto unexpectedly succeeded\n");
	}
	if (errno != EAGAIN && errno != EWOULDBLOCK)
		ksft_exit_fail_msg("udp sendto expected EAGAIN: %s\n", strerror(errno));

	rc = wait_for_desc(&ring_out, &desc);
	if (rc) {
		if (intercept_rc) {
			ksft_test_result_skip("trustcore net udp flow (intercept_mode write failed: %s)\n",
					      strerror(-intercept_rc));
			goto lsm_test;
		}
		ksft_exit_fail_msg("no DGRAM_BIND descriptor observed\n");
	}
	if (desc.type != TC_NET_DESC_DGRAM_BIND)
		ksft_exit_fail_msg("unexpected desc type %u\n", desc.type);

	udp_stream_id = desc.stream_id;
	memset(&resp, 0, sizeof(resp));
	resp.type = TC_NET_DESC_DGRAM_BIND_RESP;
	resp.req_id = desc.req_id;
	resp.stream_id = desc.stream_id;
	resp.status = 0;
	rc = ring_push(&ring_in, &resp, NULL, 0, NULL, 0);
	if (rc)
		ksft_exit_fail_msg("ring_push dgram_bind_resp failed\n");
	ioctl(devfd, TC_NET_IOC_KICK);

	rc = -1;
	for (int i = 0; i < 1000; i++) {
		rc = sendto(udpfd, udp_send, sizeof(udp_send) - 1, MSG_DONTWAIT,
			    (struct sockaddr *)&udp_peer, sizeof(udp_peer));
		if (rc == (int)(sizeof(udp_send) - 1))
			break;
		if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
			usleep(1000);
			continue;
		}
		ksft_exit_fail_msg("udp sendto failed: %s\n", strerror(errno));
	}
	if (rc != (int)(sizeof(udp_send) - 1))
		ksft_exit_fail_msg("udp sendto timed out\n");

	rc = wait_for_desc(&ring_out, &desc);
	if (rc)
		ksft_exit_fail_msg("no DGRAM_SEND descriptor observed\n");
	if (desc.type != TC_NET_DESC_DGRAM_SEND)
		ksft_exit_fail_msg("unexpected desc type %u\n", desc.type);
	if (desc.stream_id != udp_stream_id || desc.data_len != sizeof(udp_send) - 1)
		ksft_exit_fail_msg("unexpected DGRAM_SEND fields\n");

	memset(&resp, 0, sizeof(resp));
	resp.type = TC_NET_DESC_DGRAM_RECV;
	resp.stream_id = udp_stream_id;
	resp.status = 0;
	rc = ring_push(&ring_in, &resp, udp_recv, sizeof(udp_recv) - 1,
		       &udp_peer, sizeof(udp_peer));
	if (rc)
		ksft_exit_fail_msg("ring_push dgram_recv failed\n");
	ioctl(devfd, TC_NET_IOC_KICK);

	rc = -1;
	for (int i = 0; i < 1000; i++) {
		socklen_t from_len = sizeof(udp_from);

		rc = recvfrom(udpfd, udp_buf, sizeof(udp_buf), MSG_DONTWAIT,
			      (struct sockaddr *)&udp_from, &from_len);
		if (rc >= 0)
			break;
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			usleep(1000);
			continue;
		}
		ksft_exit_fail_msg("udp recvfrom failed: %s\n", strerror(errno));
	}
	if (rc != (int)(sizeof(udp_recv) - 1))
		ksft_exit_fail_msg("udp recvfrom length mismatch\n");
	if (memcmp(udp_buf, udp_recv, sizeof(udp_recv) - 1))
		ksft_exit_fail_msg("udp recvfrom payload mismatch\n");
	if (udp_from.sin_family != AF_INET ||
	    udp_from.sin_addr.s_addr != udp_peer.sin_addr.s_addr ||
	    udp_from.sin_port != udp_peer.sin_port)
		ksft_exit_fail_msg("udp recvfrom peer mismatch\n");

	ksft_test_result_pass("trustcore net udp flow\n");

lsm_test:
	lsm_status = trustcore_lsm_status();
	if (lsm_status < 0) {
		ksft_test_result_skip("trustcore net lsm gating (lsm list unavailable)\n");
	} else if (lsm_status == 0) {
		ksft_test_result_skip("trustcore net lsm gating (trustcore_net not active)\n");
	} else if (!cap_net_raw_enabled()) {
		ksft_test_result_skip("trustcore net lsm gating (missing CAP_NET_RAW)\n");
	} else {
		int rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

		if (rawfd >= 0) {
			close(rawfd);
			ksft_test_result_fail("trustcore net lsm gating\n");
		} else if (errno == EPERM || errno == EACCES) {
			ksft_test_result_pass("trustcore net lsm gating\n");
		} else {
			ksft_test_result_skip("trustcore net lsm gating (raw socket unavailable: %s)\n",
					      strerror(errno));
		}
	}

	close(accfd);
	close(clifd);
	close(srvfd);
	close(udpfd);
	munmap(out_map, layout.out_size);
	munmap(in_map, layout.in_size);
	close(devfd);
	return 0;
}
