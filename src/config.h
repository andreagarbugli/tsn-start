#ifndef CONFIG_H
#define CONFIG_H

struct config {
    char iface[100];
    char dst_mac_addr[6];
    int sk_prio;
};

int load_config(const char *filename, struct config *cfg);

int get_config_string(struct config *cfg, char *buf);

#endif // CONFIG_H
