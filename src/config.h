#ifndef CONFIG_H
#define CONFIG_H

#include <linux/if_ether.h>

#include "common.h"

#define TX_MODE_RAW (1U << 0)
#define RX_MODE_RAW (1U << 1)
#define TX_MODE_XDP (1U << 2)
#define RX_MODE_XDP (1U << 3)

#define XDP_SKB (1U << 0)
#define XDP_DRV (1U << 1)
#define XDP_ZC (1U << 2)

struct config {
    char iface[100];
    i32 queue;
    char dst_mac_addr[ETH_ALEN];
    i32 sk_prio;
    bool use_deadline_mode;
    bool receive_errors;
    bool enable_txtime;
    i32 packet_size;
    i32 vlan;
    u64 period;
    u64 offset;
    bool raw_socket;
    bool hwstamp_enabled;

    u64 time; /* test time in sec */

    u8 mode;
    u8 xdp_mode;
    
    bool realtime;
    i8 priority;
    i8 cpu;

	// BPF 
	char bpf_prog[100];
};

int load_config(const char *filename, struct config *cfg);

int get_config_string(struct config *cfg, char *buf, int len);

#endif // CONFIG_H
