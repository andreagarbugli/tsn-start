#include <ctype.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>

#include <arpa/inet.h> /* htons, inet_atoi, etc. */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#include <linux/if_xdp.h>
#include <linux/limits.h>
#include <linux/sockios.h>

#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "commands.h"
#include "common.h"
#include "config.h"
#include "connection.h"
#include "interface.h"
#include "logger.h"
#include "packet.h"
#include "state.h"
#include "utils.h"
#include "xdp_common.h"
#include "xsk_common.h"

#include "talker.skel.h"

#define NUM_FRAMES         4096 /* Frames per queue */
#define RX_BATCH_SIZE      64

bool g_running = true;
char *config_filename = "config.cfg";

void closing_handler(int signum) {
    (void)signum;
    fprintf(stdout, "\nInterrupt Received (use `quit` to exit)\n");
	fflush(stdout);
}

void do_run(struct global_state *state) {
	bool start_command = false;
	char cmd[256];
	i32 i = 0;

	fprintf(stdout, "txrx> ");
	while (g_running) {
		char c = getchar();
		if (iscntrl(c)) {
			if (c == '\n') {
				start_command = true;
			}
		} else {
			cmd[i] = c;
			i += 1;
		}

		if (start_command) {
			cmd[i] = '\0';

			do_command(cmd, i, state);

			memset(cmd, 0, sizeof(cmd));
		
			i = 0;
			start_command = false;
			if (g_running) {
				fprintf(stdout, "\ntxrx> ");
			}
		}
	}
}

i32 set_memory_limit_to_infinity() {
	struct rlimit rlim = {0};
	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;

	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		LOG_ERROR("Failed to setrlimit to RLIM_INFINITY: %s", strerror(errno));
		return -1;
	}

	return 0;
}

u32 g_xdp_flags = 0;
i32 g_ifindex = 0;

typedef struct packet_buffer {
	struct xsk_ring_prod rx_fill_ring;
	struct xsk_ring_cons tx_comp_ring;
	struct xsk_umem *umem;
	void *buffer;
} packet_buffer_t;

typedef struct xsk_options {
	u8 queue;
	u32 xdp_flags;
	u32 xdp_bind_flags;

	u16 frame_size;
	u16 frame_per_ring;
} xsk_options_t;

typedef struct xsk_info {
	struct xsk_socket *xsk;
	
	// User process managed rings (do not access directly)
	struct xsk_ring_cons rx_ring;
	struct xsk_ring_prod tx_ring;

	u32 bpf_prog_id;

	// To track current addr (pkt count * frame_size)
	u32 cur_tx;
	u32 cur_rx;

	// UMEM and rings
	packet_buffer_t pkt_buffer; 

	// TODO(garbu): some per-XDP socket stats
	u64 rx_packets;
	u64 prev_rx_packets;
	u64 tx_packets;
	u64 prev_tx_packets;
	u32 outstanding_tx;
} xsk_info_t;

struct __attribute__((packed)) xdp_packet_test {
	struct ethhdr eth;
	u8 data[64];
};

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    signal(SIGINT, closing_handler);
    signal(SIGTERM, closing_handler);
    signal(SIGABRT, closing_handler);

	struct global_state state = {0};
    
	if (argc == 2) {
		config_filename = argv[1];
	}

    if (load_config(config_filename, &state.cfg) < 0) {
        LOG_ERROR("Failed to load config");
        return -1;
    }

	set_memory_limit_to_infinity();

	char *iface = "veth0";
	i32 ifindex = 1;
	u32 xdp_flags = 0;
	u32 xdp_bind_flags = 0;
	bool need_wakeup = false;
	// xdp_socket__init()
	{
		xdp_flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;

		// init with XDP_SKB_COPY_MODE
		xdp_flags |=  XDP_FLAGS_SKB_MODE;
		xdp_bind_flags |= XDP_COPY;

		if (need_wakeup) {
			xdp_bind_flags |= XDP_USE_NEED_WAKEUP;
		}

		g_xdp_flags = xdp_flags;
		g_ifindex = ifindex;

		packet_buffer_t *packet_buffer = NULL;
		void *ubuf = NULL;
		xsk_options_t xsk_opts = {0};
		xsk_opts.frame_per_ring = 4096;
		xsk_opts.frame_size = 4096;
		// create umem
		{
			struct xsk_umem_config uconfig = {0};
			uconfig.fill_size = xsk_opts.frame_per_ring;
			uconfig.comp_size = xsk_opts.frame_per_ring;
			uconfig.frame_size = xsk_opts.frame_size;
			uconfig.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;

			u64 single_umem_ring_size = 
				xsk_opts.frame_per_ring * xsk_opts.frame_size;

			i32 ret = posix_memalign(&ubuf, getpagesize(), single_umem_ring_size);
			if (ret) {
				LOG_ERROR("Failed to posix_memalign: %s", strerror(errno));
				return -1;
			}

			packet_buffer_t *pkt_buf_tmp = calloc(1, sizeof(packet_buffer_t));

			ret = xsk_umem__create(
				&pkt_buf_tmp->umem, ubuf, single_umem_ring_size,
				&pkt_buf_tmp->rx_fill_ring, &pkt_buf_tmp->tx_comp_ring,
				&uconfig
			);
			if (ret) {
				LOG_ERROR("Failed to create UMEM: %s", strerror(errno));
				return -1;
			}

			pkt_buf_tmp->buffer = ubuf;

			u32 idx = 0;
			ret = xsk_ring_prod__reserve(
				&pkt_buf_tmp->rx_fill_ring, xsk_opts.frame_per_ring,
				&idx
			);

			if (ret != xsk_opts.frame_per_ring) {
				packet_buffer = NULL;
			} else {
				for (u16 i = 0; i < xsk_opts.frame_per_ring; ++i) {
					*xsk_ring_prod__fill_addr(&pkt_buf_tmp->rx_fill_ring, idx++) =
						i * xsk_opts.frame_size;
				}

				xsk_ring_prod__submit(
					&pkt_buf_tmp->rx_fill_ring, xsk_opts.frame_per_ring
				);

				packet_buffer = pkt_buf_tmp;
			}
		}

		if (!packet_buffer) {
			LOG_ERROR("Failed to create UMEM");
			return -1;
		}

		xsk_info_t *xsk_info = NULL;
		// create_xsk_info()
		{
			xsk_info_t *xsk_info_temp = calloc(1, sizeof(xsk_info_t));

			struct xsk_socket_config cfg = {0};
			cfg.rx_size = xsk_opts.frame_per_ring;
			cfg.tx_size = xsk_opts.frame_per_ring;

			cfg.libbpf_flags = 0;
			cfg.xdp_flags = xsk_opts.xdp_flags;
			cfg.bind_flags = xsk_opts.xdp_bind_flags;

			i32 ret = xsk_socket__create(
				&xsk_info_temp->xsk, iface,
				xsk_opts.queue, xsk_info_temp->pkt_buffer.umem,
				&xsk_info_temp->rx_ring, &xsk_info_temp->tx_ring, 
				&cfg
			);
			if (ret) {
				LOG_ERROR("Failed to create XDP socket: %s", strerror(-ret));
				return -1;
			}

			ret = bpf_get_link_xdp_id(ifindex, &xsk_info_temp->bpf_prog_id, xsk_opts.xdp_flags);
			if (ret) {
				LOG_ERROR("Failed to get XDP-PROG id from interface");
				return -1;
			}

			xsk_info = xsk_info_temp;
		}

		if (xsk_info) {
			struct xsk_socket *xsk = xsk_info->xsk;
			packet_buffer_t *buffer = &xsk_info->pkt_buffer;
			
			struct timespec ts;
			ts.tv_nsec = 0;
			ts.tv_sec = 1;
			u64 current_tx_slot = 0;

			struct xdp_packet_test test_packet = {0};
			test_packet.eth.h_proto = htons(ETH_P_TSN);
			test_packet.eth.h_dest[0] = 0x01;
			test_packet.eth.h_dest[1] = 0x00;
			test_packet.eth.h_dest[2] = 0x5e;
			test_packet.eth.h_dest[3] = 0x00;
			test_packet.eth.h_dest[4] = 0x00;
			test_packet.eth.h_dest[5] = 0x01;
			test_packet.eth.h_source[0] = 0x00;
			test_packet.eth.h_source[1] = 0x00;
			test_packet.eth.h_source[2] = 0x00;
			test_packet.eth.h_source[3] = 0x00;
			test_packet.eth.h_source[4] = 0x00;
			test_packet.eth.h_source[5] = 0x00; 
			char test_value = 'a';
			memcpy(test_packet.data, &test_value, 64);
			while (g_running)
			{
				// TODO(garbu): absolute sleep time TIMER_ABSTIME
				clock_nanosleep(CLOCK_REALTIME, 0, &ts, NULL);

				// send_packet_using_xdp()

				u8 *umem_data = xsk_umem__get_data(
					buffer->buffer, 
					current_tx_slot << XSK_UMEM__DEFAULT_FRAME_SHIFT
				);

				// TODO(garbu) build the packet
				memcpy(umem_data, &test_packet, sizeof(struct xdp_packet_test));

				u32 packet_per_send = 1; // No batch
				u32 idx = 0;
				if (xsk_ring_prod__reserve(&xsk_info->tx_ring, packet_per_send, &idx) != packet_per_send) {
					LOG_ERROR("Failed to reserve space for producer ring");
					continue;
				}

				struct xdp_desc* desc = xsk_ring_prod__tx_desc(&xsk_info->tx_ring, idx);
				desc->addr = current_tx_slot << XSK_UMEM__DEFAULT_FRAME_SHIFT;
				desc->len = sizeof(struct xdp_packet_test);

				xsk_ring_prod__submit(&xsk_info->tx_ring, packet_per_send);
				xsk_info->outstanding_tx += packet_per_send;
				current_tx_slot += packet_per_send;
				current_tx_slot %= xsk_opts.frame_per_ring;

				i32 ret = sendto(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
				if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY) {
					LOG_DEBUG("Message sent!!!!");
				}
			}
			
		} else {
			LOG_WARN("There was an error during the socket creation?");
		}
	}

	// state__init(&state);
	// do_run(&state);
	// state__clear(&state);

    return 0;
}

i32 old_test() {
	char filename[256] = {0};
	snprintf(filename, sizeof(filename), "out/xdpsock.bpf.o"); 
	u32 xsk_bind_flags = XDP_COPY;
	u32 xdp_flags = 0;
	xdp_flags &= ~XDP_FLAGS_MODES;
	i32 xsk_if_queue = 1;
	i32 ifindex = 1;
	const char *iface = "lo";
	u32 expected_prog_id = 1;
	char pin_dir[PATH_MAX];
	bool do_unload = true;
	bool reuse_maps = true;
	char prog_sec[64] = {0};
	// snprintf(prog_sec, sizeof(prog_sec), "xdp_sock"); 

	if (do_unload) {
		xdp_common__link_detach_program(ifindex, xdp_flags, expected_prog_id);
	}

	// struct bpf_map *map = NULL;
	// i32 xsks_map_fd = 0;

	struct bpf_object *bpf_obj = NULL;
	if (filename[0] == 0) { // Custom BPF program
		LOG_ERROR("Must load custom BPF-PROG");
		return -1;
	} else {
		bpf_obj = xdp_common__load_bpf_object_and_attach_xdp(
			xdp_flags, ifindex, reuse_maps, filename, pin_dir,
			prog_sec
		);

		if (!bpf_obj) {
			return -1;
		}

		// map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");

		// xsks_map_fd = bpf_map__fd(map);
		// if (xsks_map_fd < 0) {
		// 	LOG_ERROR("No xsks map found: %s (%d)", strerror(xsks_map_fd), xsks_map_fd);
		// 	return -1;
		// }
	}

	// i32 queue_max = ethtool_get_max_channels(iface);
	i32 queue_set = ethtool_get_max_channels(iface);

	xsk_container_t xsk_container = {0};
	xsk_container.num = queue_set;

	// Allocate frames according to how many queues are handled
	i32 frames_number = NUM_FRAMES;
	i32 total_frames_number = frames_number * xsk_container.num;


	// i32 err = 0;
	// {
	// 	struct btf *btf = bpf_object__btf(bpf_obj);
	// 	struct xsk_btf_info *xbi;

	// 	xbi = setup_btf_info(btf, "xdp_hints_rx_time");
	// 	if (xbi) {
	// 		/* Lookup info on required member "rx_ktime" */
	// 		if (!xsk_btf__field_member("rx_ktime", xbi,
	// 					&xdp_hints_rx_time.rx_ktime))
	// 			return -EBADSLT;
	// 		xdp_hints_rx_time.btf_type_id = xsk_btf__btf_type_id(xbi);
	// 		xdp_hints_rx_time.xbi = xbi;
	// 	}

	// 	xbi = setup_btf_info(btf, "xdp_hints_mark");
	// 	if (xbi) {
	// 		if (!xsk_btf__field_member("mark", xbi, &xdp_hints_mark.mark))
	// 			return -EBADSLT;
	// 		xdp_hints_mark.btf_type_id = xsk_btf__btf_type_id(xbi);
	// 		xdp_hints_mark.xbi = xbi;
	// 	}
	// }

	// Allow unlimited locking of memory, so all memory needed for packet
	// buffers can be locked.
	struct rlimit rlim = {0};
	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		LOG_ERROR("Failed to setrlimit(RLIMIT_MEMLOCK): %s", strerror(errno));
		return -1;
	}

	// Allocate memory for total_frames_number of the default XDP frame size
	void *packet_buffer = NULL;
	u64 packet_buffer_size = total_frames_number * FRAME_SIZE;
	if (posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size)) {
		LOG_ERROR("Can't allocate buffer memory: %s", strerror(errno));
		return -1;
	}

	xsk_umem_info_t *umem_info = xsk_umem__configure(packet_buffer, packet_buffer_size,
											 	FRAME_SIZE, total_frames_number);
	if (umem_info == NULL) {
		LOG_ERROR("Cant' create umem: %s", strerror(errno));
		return -1;
	}

	// Open and configure the AF_XDP (xsk) socket(s)

	for (i32 i = 0; i < xsk_container.num; ++i) {
		xsk_socket_info_t *xsocket_info;

		// xsk_socket__configure(
		// 		i32 xsk_if_queue, u32 xdp_flags, u32 xsk_bind_flags,
		//		const char *iface, i32 queue_id, xsk_umem_info_t umem_info,
		//		i32 xsks_map_fd
		// )
		{
			xsk_socket_info_t *xsocket_info_tmp = calloc(1, sizeof(xsk_socket_info_t));
			if (!xsocket_info_tmp) {
				return -1;
			}

			i32 _queue_id = 1;
			if (xsk_if_queue >= 0) {
				_queue_id = xsk_if_queue;
			}

			xsocket_info_tmp->queue_id = _queue_id;
			xsocket_info_tmp->umem_info = umem_info;

			struct xsk_socket_config xks_cfg = {0};
			xks_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
			xks_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
			xks_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
			xks_cfg.xdp_flags = xdp_flags;
			xks_cfg.bind_flags = xsk_bind_flags;

			LOG_DEBUG("hello 1");
			i32 ret = xsk_socket__create_shared(
				&xsocket_info_tmp->xsk, iface,
				_queue_id, umem_info->umem,
				&xsocket_info_tmp->rx, &xsocket_info_tmp->tx,
				&xsocket_info_tmp->fq, &xsocket_info_tmp->cq,
				&xks_cfg
			);
			if (ret) {
				errno = -ret;
				xsocket_info = NULL;
			}

			u32 bpf_prog_id = 0;
			ret = bpf_get_link_xdp_id(ifindex, &bpf_prog_id, xdp_flags);
			if (ret) {
				errno = -ret;
				xsocket_info = NULL;
			}

			xsocket_info = xsocket_info_tmp;
		}

		if (xsocket_info == NULL) {
			LOG_ERROR("Can't setup AF_XDP socket: %s (%d)", strerror(errno), errno);
			return -1;
		}

		xsk_container.sockets[i] = xsocket_info;

		if (xsk_fill_ring__populate(&xsocket_info->fq, umem_info, frames_number / 2)) {
			LOG_ERROR("Can't populate fill ring");
			return -1;
		}
	}

	struct pollfd fds[MAX_AF_SOCKS] = {0};

	for (i32 i = 0; i < xsk_container.num; ++i) {
		xsk_socket_info_t *xsocket_info = xsk_container.sockets[i];
		fds[i].fd = xsk_socket__fd(xsocket_info->xsk);
		fds[i].events = POLLIN;
	}

	i32 ret = 0;
	while (g_running) {
		// TODO(garbu): add poll mode
		if (false) {
			ret = poll(fds, xsk_container.num, -1);
			if (ret <= 0 || ret > 1) {
				continue;
			}
		}

		for (i32 i = 0; i < xsk_container.num; ++i) {
			xsk_socket_info_t *xsocket_info = xsk_container.sockets[i];

			u32 idx_rx = 0;
			u32 received = xsk_ring_cons__peek(&xsocket_info->rx, RX_BATCH_SIZE, &idx_rx);
			if (!received) {
				continue;
			}

			// Process received packets
			for (u32 i = 0; i < received; ++i) {
				const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsocket_info->rx, idx_rx);
				u64 addr = desc->addr;
				// u32 len = desc->len;

				u8 *packet_ptr = xsk_umem__get_data(xsocket_info->umem_info->buffer, addr);

				if (true) { // TODO(garbu): get this info only if enabled by user
					struct ethhdr *eth = (struct ethhdr *)packet_ptr;
					u16 proto = ntohs(eth->h_proto);

					fprintf(stderr, "proto = %02x", proto);
				}
			}
		}
		
	}

	// Cleanup
	for (i32 i = 0; xsk_container.num; ++i) {
		xsk_socket__delete(xsk_container.sockets[i]->xsk);
	}

	xsk_umem__delete(umem_info->umem);
	xdp_common__link_detach_program(ifindex, xdp_flags, 0);

	return 0;
}