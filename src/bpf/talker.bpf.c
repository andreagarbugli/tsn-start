#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_func(struct xdp_md *ctx) 
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
