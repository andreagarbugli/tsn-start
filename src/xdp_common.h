#if !defined(XDP_H)
#define XDP_H

// BPF stuff
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common.h"

// EXTENDED XDP SUPPORTS

typedef struct xsk_btf_info {
    // struct has;
    void *todo; // TODO(garbu): Do I need this struct?
} xsk_btf_info_t;

// END

typedef struct xdp_hints_rx_time {
    u32 btf_type_id;
    // struct xsk_btf
} xdp_hints_rx_time_t;

struct bpf_object *xdp_common__load_bpf_object_file(const char *filename, i32 ifindex);

struct bpf_object *xdp_common__load_bpf_object_and_attach_xdp(
    u32 xdp_flags, i32 ifindex,
	bool reuse_maps, const char *filename, char *pin_dir,
	char *prog_sec
);

i32 xdp_common__link_detach_all(i32 ifindex, u32 xdp_flags);

i32 xdp_common__link_detach_program(i32 ifindex, u32 xdp_flags, u32 expected_prog_id);

i32 xdp_common__link_attach(i32 ifindex, u32 xdp_flags, i32 prog_fd);

#endif // XDP_H
