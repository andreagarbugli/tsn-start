#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_sock")
int xdp_func(struct xdp_md *ctx) 
{
    return XDP_REDIRECT;
}

char _lincense[] SEC("license") = "GPL";
