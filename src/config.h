#ifndef CONFIG_H
#define CONFIG_H

#include <net/if.h>

#include "common.h"

struct config {
    char iface[100];
    char dst_mac_addr[IFHWADDRLEN];
    i32 sk_prio;
    bool use_deadline_mode;
    bool receive_errors;
    bool enable_txtime;
    i32 packet_size;
    i32 vlan;
};

int load_config(const char *filename, struct config *cfg);

int get_config_string(struct config *cfg, char *buf, int len);

#endif // CONFIG_H
