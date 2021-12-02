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
#include <sys/mman.h>
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

//#include "talker.skel.h"

#define NUM_FRAMES         4096 /* Frames per queue */
#define RX_BATCH_SIZE      64

bool g_running = true;
char *config_filename = "config.cfg";

void closing_handler(int signum) {
    (void)signum;
    fprintf(stdout, "\nInterrupt Received (use `quit` to exit)\n");
    g_running = false;
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

	bool need_wakeup;

	u64 test_packet_num;
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
	packet_buffer_t *pkt_buffer; 

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

packet_buffer_t *create_umem(xsk_options_t *opts, void *ubuf) {
	struct xsk_umem_config uconfig = {0};
	uconfig.fill_size = opts->frame_per_ring;
	uconfig.comp_size = opts->frame_per_ring;
	uconfig.frame_size = opts->frame_size;
	uconfig.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;

	u64 single_umem_ring_size = opts->frame_per_ring * opts->frame_size;

	i32 ret = posix_memalign(&ubuf, getpagesize(), single_umem_ring_size);
	if (ret) {
		LOG_ERROR("Failed to posix_memalign: %s", strerror(errno));
		return NULL;
	}

	packet_buffer_t *pkt_buf_tmp = calloc(1, sizeof(packet_buffer_t));

	ret = xsk_umem__create(&pkt_buf_tmp->umem, ubuf, single_umem_ring_size,
						   &pkt_buf_tmp->rx_fill_ring, &pkt_buf_tmp->tx_comp_ring,
						   &uconfig);
	if (ret) {
		LOG_ERROR("Failed to create UMEM: %s", strerror(errno));
		return NULL;
	}

	pkt_buf_tmp->buffer = ubuf;

	u32 idx = 0;
	ret = xsk_ring_prod__reserve(&pkt_buf_tmp->rx_fill_ring, opts->frame_per_ring, &idx);
	if (ret != opts->frame_per_ring) {
		LOG_ERROR("Failed to create UMEM (xsk_ring_prod__reserve): %s (%d)", 
				  strerror(-ret), -ret);
		return NULL;
	} 
	
	for (u16 i = 0; i < opts->frame_per_ring; ++i) {
		*xsk_ring_prod__fill_addr(&pkt_buf_tmp->rx_fill_ring, idx++) = i * opts->frame_size;
	}

	xsk_ring_prod__submit(&pkt_buf_tmp->rx_fill_ring, opts->frame_per_ring);

	return pkt_buf_tmp;
}

packet_buffer_t *xdp_socket__init(xsk_options_t *opts, i32 ifindex) {
	opts->xdp_flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;

	// init with XDP_SKB_COPY_MODE
	opts->xdp_flags |=  XDP_FLAGS_SKB_MODE;
	opts->xdp_bind_flags |= XDP_COPY;

	if (opts->need_wakeup) {
		opts->xdp_bind_flags |= XDP_USE_NEED_WAKEUP;
	}

	opts->frame_per_ring = 4096;
	opts->frame_size = 4096;

	g_xdp_flags = opts->xdp_flags;
	g_ifindex = ifindex;

	void *ubuf = NULL;
	
	return create_umem(opts, ubuf);
}

xsk_info_t *create_xsk_info(xsk_options_t *opts, packet_buffer_t *packet_buffer, 
						    const char *iface, i32 ifindex) {
	xsk_info_t *xsk_info_temp = calloc(1, sizeof(xsk_info_t));

	struct xsk_socket_config cfg = {0};
	cfg.rx_size = opts->frame_per_ring;
	cfg.tx_size = opts->frame_per_ring;

	xsk_info_temp->pkt_buffer = packet_buffer;

	cfg.libbpf_flags = 0;
	cfg.xdp_flags = opts->xdp_flags;
	cfg.bind_flags = opts->xdp_bind_flags;

	i32 ret = xsk_socket__create(&xsk_info_temp->xsk, iface, 
				     opts->queue, xsk_info_temp->pkt_buffer->umem,
				     &xsk_info_temp->rx_ring, &xsk_info_temp->tx_ring, 
				     &cfg);
	if (ret) {
		LOG_ERROR("Failed to create XDP socket: %s", strerror(-ret));
		return NULL;
	}

	ret = bpf_get_link_xdp_id(ifindex, &xsk_info_temp->bpf_prog_id, opts->xdp_flags);
	if (ret) {
		LOG_ERROR("Failed to get XDP-PROG id from interface");
		return NULL;
	}

	return xsk_info_temp;
}

const char TEST_PAYLOAD = 'a';

static void create_test_packet(struct xdp_packet_test *packet) {
	packet->eth.h_proto = htons(ETH_P_TSN);
	packet->eth.h_dest[0] = 0x01;
	packet->eth.h_dest[1] = 0x00;
	packet->eth.h_dest[2] = 0x5e;
	packet->eth.h_dest[3] = 0x00;
	packet->eth.h_dest[4] = 0x00;
	packet->eth.h_dest[5] = 0x01;
	packet->eth.h_source[0] = 0x00;
	packet->eth.h_source[1] = 0x00;
	packet->eth.h_source[2] = 0x00;
	packet->eth.h_source[3] = 0x00;
	packet->eth.h_source[4] = 0x00;
	packet->eth.h_source[5] = 0x00; 
	memcpy(packet->data, &TEST_PAYLOAD, 64);
}

i32 send_packet_using_xdp(xsk_options_t *opts, struct xdp_packet_test *packet,
	 					  xsk_info_t *xsk_info, u32 current_tx_slot) {
	u64 addr = current_tx_slot << opts->frame_size;
	u8 *umem_data = xsk_umem__get_data(xsk_info->pkt_buffer->buffer, addr);

	// TODO(garbu) build the packet
	memcpy(umem_data, packet, sizeof(struct xdp_packet_test));

	u32 packet_per_send = 1; // No batch
	u32 idx = 0;
	if (xsk_ring_prod__reserve(&xsk_info->tx_ring, packet_per_send, &idx) != packet_per_send) {
		LOG_WARN("Failed to reserve space for producer ring");
		return 0;
	}

	struct xdp_desc* desc = xsk_ring_prod__tx_desc(&xsk_info->tx_ring, idx);
	desc->addr = current_tx_slot << opts->frame_size;
	desc->len = sizeof(struct xdp_packet_test);

	xsk_ring_prod__submit(&xsk_info->tx_ring, packet_per_send);
	xsk_info->outstanding_tx += packet_per_send;
	current_tx_slot += packet_per_send;
	current_tx_slot %= opts->frame_per_ring;

	i32 ret = sendto(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret < 0) {
		LOG_ERROR("sendto error: %s (%d)", strerror(errno), errno);
		return -1;
	} else {
		LOG_DEBUG("bytes sent: %d (%s)", ret, strerror(errno));
		return 0;
	}
}

void *allocate_memory_buffer_mmap(xsk_options_t *opts, bool is_unaligned) {
	(void)is_unaligned;
	i32 optional_flags = 0; // TODO(garbu): check how to use HUGETLB or other flags
	// i32 optional_flags = is_unaligned ? MAP_HUGETLB : 0;

	void *buf = mmap(NULL, NUM_FRAMES * opts->frame_size, PROT_READ | PROT_WRITE,
					 MAP_PRIVATE | optional_flags, -1, 0);
	if (buf == MAP_FAILED) {
		LOG_ERROR("mmap failed: %s", strerror(errno));
		return NULL;
	}

	return buf;
}

void *allocate_memory_buffer_posix(xsk_options_t *opts) {
	u64 single_umem_ring_size = opts->frame_per_ring * opts->frame_size;

	i32 alignment = getpagesize();
	LOG_DEBUG("UMEM ring size: %lld (%d)", single_umem_ring_size, alignment);

	void *buf = NULL;
	i32 ret = posix_memalign(&buf, alignment, single_umem_ring_size);
	if (ret) {
		LOG_ERROR("Failed to posix_memalign: %s", strerror(errno));
		return NULL;
	}

	return buf;
}

xsk_umem_info_t *configure_xsk_umem_info(xsk_options_t *opts, void *buffer, bool is_unaligned) {
	u32 umem_flags = is_unaligned ? XDP_UMEM_UNALIGNED_CHUNK_FLAG : 0;

	struct xsk_umem_config umem_config = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = opts->frame_size,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = umem_flags
	};

	xsk_umem_info_t *umem_tmp = calloc(1, sizeof(xsk_umem_info_t));
	if (!umem_tmp) {
		LOG_WARN("(%s) - calloc failed: %s", __func__, strerror(errno));
		return NULL;
	}

	LOG_DEBUG("buffer address: %p", buffer);

	u64 size = opts->frame_size * NUM_FRAMES; // TODO(garbu): dynamic frame number?
	i32 ret = xsk_umem__create(&umem_tmp->umem, buffer, size, 
							   &umem_tmp->init_fq, &umem_tmp->init_cq, 
							   &umem_config);
	if (ret) {
		LOG_ERROR("Failed xsk_umem_create: %s", strerror(-ret));
		return NULL;
	}

	umem_tmp->buffer = buffer;
	return umem_tmp;
}

typedef struct interface_min {
	char name[IF_NAMESIZE];
	u32 index;
} interface_min_t;

// NOTE(garbu): currently we support only one socket per interface
xsk_socket_info_t *configure_xsk_socket_for_tx(xsk_options_t *opts, xsk_umem_info_t *umem_info,
											   interface_min_t *iface) {
	xsk_socket_info_t *xsk_info_tmp = calloc(1, sizeof(xsk_socket_info_t));
	if (!xsk_info_tmp) {
		LOG_WARN("(%s) - calloc failed: %s", __func__, strerror(errno));
		return NULL;
	}

	xsk_info_tmp->umem_info = umem_info;
	
	struct xsk_socket_config xsk_config = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.libbpf_flags = 0, // we can change this to support multi socket.
		.xdp_flags = opts->xdp_flags,
		.bind_flags = opts->xdp_bind_flags
	};

	LOG_TRACE("Creating the XDP socket `xsk_socket__create` interface %s (%d)",
		      iface->name, iface->index);
	i32 ret = xsk_socket__create(&xsk_info_tmp->xsk, iface->name, opts->queue,
						   	     umem_info->umem, NULL, &xsk_info_tmp->tx, &xsk_config);
	if (ret) {
		LOG_ERROR("Failed to create an XDP socket for TX: %s", strerror(-ret));
		return NULL;
	}

//	LOG_TRACE("Getting the XDP-PROG ID from the interface (bpf_get_link_xdp_id)");
//	ret = bpf_get_link_xdp_id(iface->index, &xsk_info_tmp->bpf_prog_id, opts->xdp_flags);
//	if (ret) {
//		LOG_ERROR("Failed to get the XDP-PROG ID: %s", strerror(-ret));
//		return NULL;
//	}

	// TODO(garbu): init some xsk_info_t app specific stats?

	return xsk_info_tmp;
}

#define PAYLOAD_SIZE 64 
#define PKT_SIZE PAYLOAD_SIZE - ETH_FCS_LEN

static void kick_tx(struct xsk_socket_info *xsk_info)
{
	int ret = sendto(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret >= 0 || errno == ENOBUFS 
		|| errno == EAGAIN || errno == EBUSY 
		|| errno == ENETDOWN) {
		return;
	}

	LOG_WARN("In teoria c'e' un errore");
}

i32 start_tx_only(xsk_options_t *opts, xsk_socket_info_t *xsk_info) {
	u32 frame_nb = 0;
	i32 pkt_count = 0;
	while (pkt_count < opts->test_packet_num) {
		LOG_TRACE("usleep");
		usleep(100000);


		LOG_TRACE("sending");
		u32 packet_per_send = 1; // No batch
		u32 idx = 0;
		i32 ret = xsk_ring_prod__reserve(&xsk_info->tx, packet_per_send, &idx);
		// if (ret < packet_per_send) {
			// if (!xsk_info->outstanding_tx) {
			// 	LOG_TRACE("TRACE 1");
			// 	return -1;
			// }

			if (!opts->need_wakeup || xsk_ring_prod__needs_wakeup(&xsk_info->tx)) {
				// xsk->app_stats.tx_wakeup_sendtos++;
				LOG_TRACE("TRACE 2: kick_tx");
				kick_tx(xsk_info);
			}

			u32 idx2;
			u32 rcvd = xsk_ring_cons__peek(&xsk_info->umem_info->init_cq, packet_per_send, &idx2);
			if (rcvd > 0) {
				LOG_TRACE("TRACE 3");
				xsk_ring_cons__release(&xsk_info->umem_info->init_cq, rcvd);
				xsk_info->outstanding_tx -= rcvd;
			}
			// LOG_WARN("Failed to reserve space for producer ring: %d", ret);
			// return 0;
		// }

		// TODO(garbu): complete_tx_only

		struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk_info->tx, idx);
		tx_desc->addr = frame_nb * opts->frame_size;
		tx_desc->len = PKT_SIZE;
	
		xsk_ring_prod__submit(&xsk_info->tx, packet_per_send);
		xsk_info->outstanding_tx += packet_per_send;
		frame_nb += packet_per_send;
		frame_nb %= NUM_FRAMES;

		// i32 ret = sendto(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
		// if (ret < 0) {
		// 	LOG_ERROR("sendto error: %s (%d)", strerror(errno), errno);
		// 	return -1;
		// } else {
		// 	LOG_DEBUG("bytes sent: %d (%s)", ret, strerror(errno));
		// 	return 0;
		// }
		pkt_count += packet_per_send;
	
		if (!g_running) {
			break;
		}
	}

	return 0;
}

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

	xsk_options_t xsk_opts = {
		.frame_size = 4096,
		.frame_per_ring = 4096,
		.need_wakeup = false,
		.queue = 1,
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
		.xdp_bind_flags = XDP_COPY,
		.test_packet_num = 20,
	};

	if (xsk_opts.need_wakeup) {
		xsk_opts.xdp_bind_flags |= XDP_USE_NEED_WAKEUP;
	}

	xsk_opts.xdp_flags |= XDP_FLAGS_SKB_MODE;

	i32 ret = 0;

	LOG_TRACE("Allocating memory for the UMEM");
	void *buffer = allocate_memory_buffer_posix(&xsk_opts); 
	if (!buffer) {
		LOG_ERROR("Failed tu allocate the memory buffer: exiting");
		return -1;
	}

	LOG_TRACE("Configuring the UMEM info");
	xsk_umem_info_t *umem_info = configure_xsk_umem_info(&xsk_opts, buffer, false);
	if (!umem_info) {
		LOG_ERROR("Failed tu configure umem info: exiting");
		ret = -2;
		goto clean;
	}

	interface_min_t iface = { .index = 3 };
	memcpy(iface.name, "enp3s0", IF_NAMESIZE - 1);

	LOG_TRACE("Configuring the XDP socket only for TX");
	xsk_socket_info_t *xsk_info = configure_xsk_socket_for_tx(&xsk_opts, umem_info, &iface);
	if (!xsk_info) {
		LOG_ERROR("Failed to configure a new XDP socket for TX");
		ret = -3;
		goto clean;
	}

	u8 pkt_data[XSK_UMEM__DEFAULT_FRAME_SIZE];
	struct ethhdr *eth_hdr = (struct ethhdr *)pkt_data;

	// Ethernet header
	memcpy(eth_hdr->h_source, "\x3c\xfd\xfe\x9e\x7f\x71", ETH_ALEN);
	memcpy(eth_hdr->h_dest, "\x01\x00\x5e\x00\x00\x01", ETH_ALEN);
	eth_hdr->h_proto = htons(ETH_P_TSN);

	// Payload 
	memcpy(pkt_data + ETH_HLEN, &TEST_PAYLOAD, PAYLOAD_SIZE);

	LOG_TRACE("Generating all packets to be sent");
	for (i32 i = 0; i < NUM_FRAMES; i++) {
		u64 addr = i * xsk_opts.frame_size;
		memcpy(xsk_umem__get_data(umem_info->buffer, addr), pkt_data, PKT_SIZE);
	}
	
	start_tx_only(&xsk_opts, xsk_info);

	LOG_TRACE("running...");

clean:
	LOG_TRACE("Cleaning all the stuff");

	do {
		u32 current_prog_id = 0;

		if (bpf_get_link_xdp_id(iface.index, &current_prog_id, xsk_opts.xdp_flags)) {
			LOG_ERROR("Failed to get current XDP-PROG from interface %s", iface.name);
			break;
		}

		if (xsk_info->bpf_prog_id == current_prog_id) {
			bpf_set_link_xdp_fd(iface.index, -1, xsk_opts.xdp_flags);
		} else if (!current_prog_id) {
			LOG_WARN("Couldn't find a program on the given interface %s", iface.name);
		} else {
			LOG_WARN("Program in interface %s in changed, not removing", iface.name);
		}
	} while (false);

	free(buffer);
	xsk_socket__delete(xsk_info->xsk);
	xsk_umem__delete(umem_info->umem);
	free(umem_info);
	free(xsk_info);

	// state__init(&state);
	// do_run(&state);
	// state__clear(&state);

    return ret;
}

i32 old_test() {
	char *iface = "enp3s0";
	i32 ifindex = 1;
	xsk_options_t xsk_opts = {0};
	xsk_opts.need_wakeup = false;
	
	packet_buffer_t *packet_buffer = xdp_socket__init(&xsk_opts, ifindex);
	if (!packet_buffer) {
		LOG_ERROR("Failed to init XDP socket: %p", packet_buffer);
		return -1;
	}

	xsk_info_t *xsk_info = create_xsk_info(&xsk_opts, packet_buffer, iface, ifindex);
	if (!xsk_info) {
		LOG_ERROR("Failed to create xsk_info_t");
		return -1;
	}

	struct xdp_packet_test test_packet;
	create_test_packet(&test_packet);
	
	u64 current_tx_slot = 0;
	struct timespec ts = { .tv_nsec = 0, .tv_sec = 1 };
	while (g_running)
	{
		// TODO(garbu): absolute sleep time TIMER_ABSTIME
		clock_nanosleep(CLOCK_REALTIME, 0, &ts, NULL);

		i32 ret = send_packet_using_xdp(&xsk_opts, &test_packet, xsk_info, current_tx_slot);
		if (ret < 0) {
			LOG_ERROR("send_packet_using_xdp");
		}
	}

	return 0;
}
