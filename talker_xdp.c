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

#define DEFAULT_VALUE 4096

typedef struct interface_min {
	char name[IF_NAMESIZE];
	u32 index;
	u32 queue_id;
} interface_min_t;

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

void *allocate_umem_area_with_posix_memalign(u64 umem_ring_size) {
	i32 alignment = getpagesize();

	void *buf = NULL;
	i32 ret = posix_memalign(&buf, alignment, umem_ring_size);
	if (ret) {
		LOG_ERROR("Failed to posix_memalign: %s", strerror(errno));
		return NULL;
	}

	return buf;
}

/**
 * @brief UMEM is associated to a netdev and a specific queue id of that netdev.
 * It is created and configured (chunk size, headroom, start address and size) 
 * by using the XDP_UMEM_REG setsockopt system call. UMEM uses two rings: FILL and
 * COMPLETION. Each socket associated with the UMEM must have an RX queue, TX queue or both.
 * 
 * @param umem 
 * @param params 
 * @param is_unaligned 
 * @return i32 
 */
i32 xdp_umem__init(xdp_umem_t *umem, xsk_config_params_t *params, bool is_unaligned) {
	u32 umem_flags = is_unaligned ? XDP_UMEM_UNALIGNED_CHUNK_FLAG : 0;

	struct xsk_umem_config umem_config = {
		.fill_size = params->number_of_desc_fill_queue * 2,
		.comp_size = params->number_of_desc_comp_queue,
		.frame_size = params->frame_size,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = umem_flags
	};

	u64 size = params->frame_size * params->frames_per_ring; // TODO(garbu): dynamic frame number?
	i32 ret = xsk_umem__create(&umem->umem, umem->buffer_area, size, 
							   &umem->fill_queue, &umem->comp_queue, 
							   &umem_config);
	if (ret) {
		LOG_ERROR("Failed xsk_umem_create: %s", strerror(-ret));
		return -1;
	}

	if (params->flags & XSK_CONFIG_FLAGS_RX) {
		LOG_INFO("Configuring the UMEM for RX");
		u32 frame_per_ring = params->number_of_desc_fill_queue;
		u32 idx = 0;
		u32 sret = xsk_ring_prod__reserve(&umem->fill_queue, frame_per_ring, &idx);
		if (sret != frame_per_ring) {
			return -1;
		}

		for (u64 i = 0; i < frame_per_ring; i++) {
			u64 *addr = (u64 *)xsk_ring_prod__fill_addr(&umem->fill_queue, idx++);
			*addr = i * params->frame_size;
		}

		xsk_ring_prod__submit(&umem->fill_queue, frame_per_ring);
	}

	return 0;
}

/**
 * @brief Configure AF_XDP socket to redirect frames to a memory buffer in 
 *  a user-space application XSK has two rings: the RX ring and the TX ring
 *  A socket can receive packets on the RX ring and it can send packets on the TX ring
 * 
 * @param params 
 * @return i32 
 */
xdp_socket_t *xdp_connection__create(xsk_config_params_t *params, interface_min_t *iface) {
	i32 ret = set_memory_limit_to_infinity();
	if (ret < 0) {
		return NULL;
	}

	xdp_socket_t *xdp_sock = calloc(1, sizeof(xdp_socket_t));
	if (!xdp_sock) {
		LOG_WARN("(%s) - calloc failed: %s", __func__, strerror(errno));
		return NULL;
	}

	LOG_TRACE("Configuring the UMEM info");
	xdp_sock->umem = calloc(1, sizeof(xdp_umem_t));
	if (!xdp_sock->umem) {
		LOG_WARN("(%s) - calloc failed: %s", __func__, strerror(errno));
		free(xdp_sock);
		return NULL;
	}

	/*
	 * NOTE(garbu): potremmo mettere la funzione di allocazione del buffer
	 * 	di memoria per la UMEM all'interno della funzione che configura 
	 *  proprio la UMEM, ma facendo questa cosa fuori da essa, possiamo
	 *  sfruttare diversi meccanismi di allocazione della memoria (es. mmap, hugepages).
	 */
	LOG_TRACE("Allocating memory for the UMEM");
	u64 single_umem_ring_size = params->frames_per_ring * params->frame_size;
	xdp_sock->umem->buffer_area = allocate_umem_area_with_posix_memalign(single_umem_ring_size); 
	if (!xdp_sock->umem->buffer_area) {
		LOG_ERROR("Failed tu allocate the memory buffer: exiting");
		free(xdp_sock->umem);
		free(xdp_sock);
		return NULL;
	}

	ret = xdp_umem__init(xdp_sock->umem, params, false);
	if (ret < 0) {
		LOG_ERROR("Failed tu configure umem info: exiting");
		free(xdp_sock->umem->buffer_area);
		free(xdp_sock->umem);
		free(xdp_sock);
		return NULL;
	}

	xdp_sock->outstanding_tx = 0;
	// xdp_sock->rx_idx = 0;
	// xdp_sock->tx_idx = 0;
	
	struct xsk_socket_config xsk_config = {
		.rx_size = params->number_of_desc_fill_queue,
		.tx_size = params->number_of_desc_comp_queue,
		.libbpf_flags = 0, // we can change this to support multi socket.
		.xdp_flags = params->xdp_flags,
		.bind_flags = params->xdp_bind_flags
	};

	struct xsk_ring_prod *tx_ring = params->flags & XSK_CONFIG_FLAGS_TX 
									? &xdp_sock->tx_ring 
									: NULL;  
	struct xsk_ring_cons *rx_ring = params->flags & XSK_CONFIG_FLAGS_RX 
									? &xdp_sock->rx_ring 
									: NULL;  

	LOG_TRACE("Creating the XDP socket `xsk_socket__create` interface %s (%d)",
		      iface->name, iface->index);
	ret = xsk_socket__create(&xdp_sock->xsk_fd, 
								 iface->name, iface->queue_id,
						   	     xdp_sock->umem->umem, 
								 rx_ring, tx_ring, 
								 &xsk_config);

	if (ret == ENOTSUP) {
        LOG_ERROR("Failed to create XDP connection. xsk_socket__create not supported.");
        free(xdp_sock->umem->buffer_area);
        (void)xsk_umem__delete(xdp_sock->umem->umem);
        free(xdp_sock->umem);
        free(xdp_sock);
        return NULL;
    } else if (ret < 0) {
		LOG_ERROR("Failed to create XDP connection. xsk_socket__create failed: %s",
		 		  strerror(errno));
		free(xdp_sock->umem->buffer_area);
        (void)xsk_umem__delete(xdp_sock->umem->umem);
        free(xdp_sock->umem);
        close(xsk_socket__fd(xdp_sock->xsk_fd));
        bpf_set_link_xdp_fd(iface->index, -1, params->xdp_flags);
        free(xdp_sock);
        return NULL;
    }

	LOG_TRACE("Getting the XDP-PROG ID from the interface (bpf_get_link_xdp_id)");
	ret = bpf_get_link_xdp_id(iface->index, &xdp_sock->bpf_prog_id, params->xdp_flags);
	if (ret) {
		LOG_ERROR("Failed to get the XDP-PROG ID: %s", strerror(-ret));
		free(xdp_sock->umem->buffer_area);
        (void)xsk_umem__delete(xdp_sock->umem->umem);
        free(xdp_sock->umem);
        close(xsk_socket__fd(xdp_sock->xsk_fd));
        bpf_set_link_xdp_fd(iface->index, -1, params->xdp_flags);
        free(xdp_sock);
        return NULL;
	}

	return xdp_sock;
}

i32 xdp_connection__send(xdp_socket_t *xdp_sock, xsk_config_params_t *params, u8 *data, size_t len) {
	u8 *packet_buffer = xsk_umem__get_data(xdp_sock->umem->buffer_area, 
										   xdp_sock->cur_tx * params->frame_size);
	
	struct ethhdr *eth_hdr = (struct ethhdr *)packet_buffer;

	// Ethernet header
	memcpy(eth_hdr->h_source, "\x3c\xfd\xfe\x9e\x7f\x71", ETH_ALEN);
	memcpy(eth_hdr->h_dest, "\x01\x00\x5e\x00\x00\x01", ETH_ALEN);
	eth_hdr->h_proto = htons(ETH_P_TSN);

	size_t packet_len = len + ETH_HLEN;
	u8 *payload_ptr = packet_buffer + ETH_HLEN;

	if (packet_len > params->frame_size) {
		LOG_ERROR("Packet is too big");
		return -1;
	}

	// Set the payload with the data to be sent
	memcpy(payload_ptr, data, len);

	// NOTE(garbu): we now support the sending of one message at time
	// TODO(garbu): add batch support?number_of_packets?
	u32 idx = 0;
	u32 number_of_packets = 1;
	if (xsk_ring_prod__reserve(&xdp_sock->tx_ring, number_of_packets, &idx) 
		!= number_of_packets
	) {
		LOG_ERROR("XDP connection send failed. xsk_ring_prod__reserve failed.");
		return -1;
	}

	struct xdp_desc *desc = xsk_ring_prod__tx_desc(&xdp_sock->tx_ring, idx);
	desc->addr = xdp_sock->cur_rx * params->frame_size;
	desc->len = packet_len;

	xsk_ring_prod__submit(&xdp_sock->tx_ring, number_of_packets);
	xdp_sock->outstanding_tx += number_of_packets;

	// Increase the current tx pointer, rollover if exceed
	xdp_sock->cur_tx += 0;
	xdp_sock->cur_tx %= params->frames_per_ring;

	if (!params->need_wakeup || xsk_ring_prod__needs_wakeup(&xdp_sock->tx_ring)) {
		i32 ret = sendto(xsk_socket__fd(xdp_sock->xsk_fd), NULL, 0, MSG_DONTWAIT, NULL, 0);
		if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY) {
			u32 rcvd = xsk_ring_cons__peek(&xdp_sock->umem->comp_queue, 1, &idx);
			if (rcvd > 0) {
				xsk_ring_cons__release(&xdp_sock->umem->comp_queue, rcvd);
				xdp_sock->outstanding_tx -= rcvd;
				xdp_sock->stats.tx_packets += rcvd;
			}

			return 0;
		}
	}

	LOG_ERROR("XDP connection send failed: %s", strerror(errno));
	return -1;
}

i32 xdp_connection__receive(xdp_socket_t *xdp_sock) {
	u32 rx_idx = 0;
	u32 rcvd = xsk_ring_cons__peek(&xdp_sock->rx_ring, 1, &rx_idx);
	if (!rcvd) {
		return -1;
	}

	u32 fq_idx = 0;
	u32 ret = xsk_ring_prod__reserve(&xdp_sock->umem->fill_queue, rcvd, &fq_idx);
	while (ret != rcvd) {
		// if (ret < 0) {
		// 	LOG_ERROR("Failed");
		// 	return -1;
		// }

		ret = xsk_ring_prod__reserve(&xdp_sock->umem->fill_queue, rcvd, &fq_idx);
	}

	for (u64 i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xdp_sock->rx_ring, rx_idx);

		u8 *packet = xsk_umem__get_data(xdp_sock->umem->buffer_area, desc->addr);

		if (!desc->len) {
			LOG_WARN("Received a packet with ZERO length");
			continue;
		}

		u64 rx_timestamp = get_realtime_ns();
		
		custom_payload_t *payload_ptr = (custom_payload_t*)(packet + ETH_HLEN);
		// Handle Packet 

		LOG_INFO("rx: %lld\ttx: %lld\tlat: %lld", 
				 rx_timestamp, payload_ptr->tx_timestamp,
				 rx_timestamp - payload_ptr->tx_timestamp);

	}

	xsk_ring_prod__submit(&xdp_sock->umem->fill_queue, rcvd);
	xsk_ring_cons__release(&xdp_sock->rx_ring, rcvd);

	xdp_sock->stats.rx_packets += rcvd;

	return 0;
}

void xdp_connection__close(xdp_socket_t *xdp_sock, 
						  xsk_config_params_t *params,
						  interface_min_t *iface) 
{
	do {
		u32 current_prog_id = 0;
		if (bpf_get_link_xdp_id(iface->index, &current_prog_id, params->xdp_flags)) {
			LOG_ERROR("Failed to get current XDP-PROG from interface %s", iface->name);
			break;
		}

		if (xdp_sock->bpf_prog_id == current_prog_id) {
			bpf_set_link_xdp_fd(iface->index, -1, params->xdp_flags);
		} else if (!current_prog_id) {
			LOG_WARN("Couldn't find a program on the given interface %s", iface->name);
		} else {
			LOG_WARN("Program in interface %s in changed, not removing", iface->name);
		}
	} while (false);

	xsk_socket__delete(xdp_sock->xsk_fd);
	(void)xsk_umem__delete(xdp_sock->umem->umem);
	free(xdp_sock->umem->buffer_area);
	free(xdp_sock->umem);
	free(xdp_sock);
}

void do_tx(struct global_state *state, xdp_socket_t *sock, xsk_config_params_t *params) {
	struct timespec ts;
    u64 looping_ts = get_realtime_ns() + NSEC_PER_SEC;
    u64 txtime = 0;
	u64 period = state->cfg.period;
	u64 offset = state->cfg.offset;
    setup_looping_ts_and_txtime(&ts, &looping_ts, &txtime, period, offset);

	u8 data[64] = {0};
	u8 *data_ptr = &data[0];
	// memcpy(data_ptr, "\x3c\xfd\xfe\x9e", 4);
	custom_payload_t *payload_ptr = (custom_payload_t *)(data_ptr);

	i32 pkt_count = 0;
	while (1 && pkt_count < state->cfg.offset * 100) {
		i32 sleep_ret = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, NULL);
		if (sleep_ret) {
			LOG_WARN("Failed to sleep %d: %s", sleep_ret, strerror(sleep_ret));
			break;
		}   

		payload_ptr->seq = pkt_count;
		payload_ptr->tx_timestamp = get_realtime_ns();

		LOG_INFO("tx time: %lld", payload_ptr->tx_timestamp);
		xdp_connection__send(sock, params, data, sizeof(data));
		
		update_lopping_and_txtime(&ts, &looping_ts, &txtime, period);

		pkt_count += 1;

		if (!g_running) {
			break;
		}
	}
}

void do_rx(xdp_socket_t *sock) {
	LOG_INFO("Start receiving packets...");
	while (1) {
		(void)xdp_connection__receive(sock);

		if (!g_running) {
			break;
		}
	}
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

	interface_min_t iface = { .index = if_nametoindex(state.cfg.iface) };
	memcpy(iface.name, state.cfg.iface, IF_NAMESIZE - 1);
	iface.queue_id = state.cfg.queue;

	xsk_config_params_t xsk_cfg_params = {
		.frame_size = DEFAULT_VALUE,
		.frames_per_ring = DEFAULT_VALUE,
		.number_of_desc = DEFAULT_VALUE,
		.number_of_desc_comp_queue = DEFAULT_VALUE,
		.number_of_desc_fill_queue = DEFAULT_VALUE,
		.flags = XSK_CONFIG_FLAGS_TX,
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
		.xdp_bind_flags = 0,
		.need_wakeup = false
	};

	switch (state.cfg.xdp_mode) {
		case XDP_DRV:
			xsk_cfg_params.xdp_flags |= XDP_FLAGS_DRV_MODE;
			xsk_cfg_params.xdp_bind_flags = XDP_COPY;
			break;
		case XDP_ZC: // WARN(garbu): zero-copy breaks the fucking system if `igc` driver is used.
			xsk_cfg_params.xdp_bind_flags |= XDP_ZEROCOPY;
			break;
		default: /* XDP_SKB */
			xsk_cfg_params.xdp_flags |= XDP_FLAGS_SKB_MODE;
			xsk_cfg_params.xdp_bind_flags = XDP_COPY;
			break;

	}

	if (state.cfg.mode == RX_MODE_XDP) {
		xsk_cfg_params.flags = 0;
		xsk_cfg_params.flags = XSK_CONFIG_FLAGS_RX;
	}

	xdp_socket_t *xdp_socket = xdp_connection__create(&xsk_cfg_params, &iface);
	if (!xdp_socket) {
		LOG_ERROR("Failed to create an XDP connection");
		return -1;
	}

	if (state.cfg.mode == RX_MODE_XDP) {
		do_rx(xdp_socket);
	} else {
		LOG_INFO("Starting as a TALKER");
		do_tx(&state, xdp_socket, &xsk_cfg_params);
	}
	
	LOG_TRACE("Cleaning all the stuff");
	xdp_connection__close(xdp_socket, &xsk_cfg_params, &iface);

	// state__init(&state);
	// do_run(&state);
	// state__clear(&state);

    return 0;
}