#ifndef XSK_COMMON_H
#define XSK_COMMON_H

#include <bpf/xsk.h>

#include <linux/if_link.h>

#include "common.h"

#define MAX_AF_SOCKS	64
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE /* 4096 */
#define INVALID_UMEM_FRAME UINT64_MAX

typedef struct xdp_umem {
    struct xsk_ring_prod fill_queue;
    struct xsk_ring_cons comp_queue;
    struct xsk_umem *umem;
    char *frames;
    void *buffer_area;
    i32 fd;
} xdp_umem_t;

typedef struct stats_record {
    u64 timestamp;
    u64 rx_packets;
    u64 rx_bytes;
    u64 tx_packets;
    u64 tx_bytes;
} stats_record_t;

typedef struct xdp_socket {
    struct xsk_ring_cons rx_ring;
    struct xsk_ring_prod tx_ring;

    struct xsk_socket *xsk_fd;
    xdp_umem_t *umem;
	u32 bpf_prog_id;
    u32 cur_tx;
    u32 cur_rx;

    u32 outstanding_tx;
    // Stats
    stats_record_t stats;
    stats_record_t prev_stats;

} xdp_socket_t;

#define XSK_CONFIG_FLAGS_TX (1U << 0)
#define XSK_CONFIG_FLAGS_RX (1U << 1)
#define XSK_CONFIG_FLAGS_BOTH (XSK_CONFIG_FLAGS_TX | XSK_CONFIG_FLAGS_RX)

typedef struct xsk_config_params {
	u16 frame_size;
	u16 frames_per_ring;
    u16 number_of_desc;
    u16 number_of_desc_fill_queue;
    u16 number_of_desc_comp_queue;
    bool need_wakeup;
    u8 flags;
    u32 xdp_flags;
    u32 xdp_bind_flags;
} xsk_config_params_t;

#endif // XSK_COMMON_H