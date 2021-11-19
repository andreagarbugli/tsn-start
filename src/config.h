#ifndef CONFIG_H
#define CONFIG_H

#include <linux/if_ether.h>

#include "common.h"

struct config {
    char iface[100];
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
    
    bool realtime;
    i8 priority;
    i8 cpu;
};

int load_config(const char *filename, struct config *cfg);

int get_config_string(struct config *cfg, char *buf, int len);

#endif // CONFIG_H
