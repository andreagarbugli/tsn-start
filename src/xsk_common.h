#ifndef XSK_COMMON_H
#define XSK_COMMON_H

#include <bpf/xsk.h>

#include "common.h"

#define MAX_AF_SOCKS	64
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE /* 4096 */
#define INVALID_UMEM_FRAME UINT64_MAX

typedef struct mem_frame_allocator {
    u32 umem_frame_free;
    u32 umem_frame_max;
    u64 *umem_frame_addr;
} mem_frame_allocator_t;

typedef struct xsk_umem_info {
    struct xsk_ring_prod init_fq;
    struct xsk_ring_cons init_cq;
    struct xsk_umem *umem;
    void *buffer;
    mem_frame_allocator_t mem_allocator;
} xsk_umem_info_t;

typedef struct stats_record {
    u64 timestamp;
    u64 rx_packets;
    u64 rx_bytes;
    u64 tx_packets;
    u64 tx_bytes;
} stats_record_t;

typedef struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    xsk_umem_info_t *umem_info;
    struct xsk_socket *xsk;
    struct xsk_ring_cons cq;
    struct xsk_ring_prod fq;

    u32 outstanding_tx;
    i32 queue_id;

    stats_record_t stats;
    stats_record_t prev_stats;
} xsk_socket_info_t;

typedef struct xsk_container {
    xsk_socket_info_t *sockets[MAX_AF_SOCKS];
    i32 num;
} xsk_container_t;


xsk_umem_info_t *xsk_umem__configure(
    void *buffer, u64 buffer_size,
    u32 frame_size, u32 frames_number
);

i32 xsk_fill_ring__populate(
    struct xsk_ring_prod *fq,
    xsk_umem_info_t *umem_info,
    i32 frames_number
);

        
#endif // XSK_COMMON_H