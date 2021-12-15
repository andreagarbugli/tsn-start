#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>

#include "common.h"
#include "config.h"
#include "logger.h"

#define BUFSIZE 4096

bool is_valid_character(const char value) {
    return (value >= 'a' && value <= 'z') 
            || (value >= 'A' && value <= 'Z')
            || (value >= '0' && value <= '9')
            || value == '_';
}

bool is_empty_line(const char *line, int len) {
    if (len == 0) {
        return true;
    }
    
    bool is_empty = true;
    for (int i = 0; i < len; i++) {
        if (is_valid_character(line[i]) || line[i] == '=') {
            is_empty = false;
        }
    }

    return is_empty;
}

static int get_property_name_and_value(
    const char  *line, 
    int len, 
    char *name, 
    char *value
) {
    int i = 0;
    int j = 0;
    // get property name
    while (line[i] != '=') {
        if (i > len) {
            return -1;
        }

        if (is_valid_character(line[i])) {
            name[j] = line[i];
            j += 1;
        }

        i += 1;
    }

    // end of file after '='
    if (i > len) {
        return -1;
    }

    // get the value of the property
    // TODO(garbu): check for whitespaces
    j = 0;
    for (i += 1; i <= len; i += 1) {
        value[j] = line[i];
        j += 1;
    }

    return 0;
}


int load_config(const char *filename, struct config *cfg) {
    int config_file = open(filename, O_RDONLY);
    if (config_file < 0) {
        LOG_ERROR("impossible to read config.cfg file: %s", strerror(errno));
        return -1;
    }

    char line[BUFSIZE] = { 0 };
    int line_idx = 0;
    
    char buf[BUFSIZE] = {0};
    ssize_t bytes_read = 0; 
    while ((bytes_read = read(config_file, buf, BUFSIZE)) > 0) {
        int buf_idx = 0;
        while (buf_idx <= bytes_read) {
            while (buf_idx <= bytes_read && buf[buf_idx] != '\n') {
                line[line_idx++] = buf[buf_idx++];
            }

            // consume the '\n'
            buf_idx += 1;

            if (!is_empty_line(line, line_idx)) {
                char name[100] = { 0 };
                char value[50] = { 0 };
                if (get_property_name_and_value(line, line_idx, name, value) < 0) {
                    // TODO(garbug): check for error
                }

                char *endptr = NULL;
                errno = 0;
                if (strncmp(name, "SK_PRIO", strnlen(name, BUFSIZE)) == 0) {
                    int val = strtol(value, &endptr, 10);
                    if (errno || endptr != value) {
                        cfg->sk_prio = val;
                    }
                }

                if (strncmp(name, "ENABLE_TXTIME", strnlen(name, BUFSIZE)) == 0) {
                    if (strncmp(value, "TRUE", strnlen(value, BUFSIZE)) == 0) {
                        cfg->enable_txtime = true;
                    }
                }

                if (strncmp(name, "PACKET_SIZE", strnlen(name, BUFSIZE)) == 0) {
                    int val = strtol(value, &endptr, 10);
                    if (errno || endptr != value) {
                        cfg->packet_size = val;
                    }
                }

                if (strncmp(name, "MODE", strnlen(name, BUFSIZE)) == 0) {
                    if (strncmp(value, "TX_XDP", strnlen(value, BUFSIZE)) == 0) {
                        cfg->mode = TX_MODE_XDP;
                    } else if (strncmp(value, "RX_XDP", strnlen(value, BUFSIZE)) == 0) {
                        cfg->mode = RX_MODE_XDP;
                    } else if (strncmp(value, "RX_RAW", strnlen(value, BUFSIZE)) == 0) {
                        cfg->mode = RX_MODE_RAW;
                    } else {
                        cfg->mode = TX_MODE_RAW;
                    }
                }

                if (strncmp(name, "XDP_MODE", strnlen(name, BUFSIZE)) == 0) {
                    if (strncmp(value, "DRV", strnlen(value, BUFSIZE)) == 0) {
                        cfg->xdp_mode = XDP_DRV;
                    } else if (strncmp(value, "ZC", strnlen(value, BUFSIZE)) == 0) {
                        cfg->xdp_mode = XDP_ZC;
                    } else if (strncmp(value, "RX_RAW", strnlen(value, BUFSIZE)) == 0) {
                        cfg->xdp_mode = XDP_SKB;
                    }
                }

                if (strncmp(name, "VLAN", strnlen(name, BUFSIZE)) == 0) {
                    int val = strtol(value, &endptr, 10);
                    if (errno || endptr != value) {
                        cfg->vlan = val;
                    }
                }

                if (strncmp(name, "PRIORITY", strnlen(name, BUFSIZE)) == 0) {
                    int val = strtol(value, &endptr, 10);
                    if (errno || endptr != value) {
                        cfg->priority = val;
                    }
                }

                if (strncmp(name, "CPU", strnlen(name, BUFSIZE)) == 0) {
                    int val = strtol(value, &endptr, 10);
                    if (errno || endptr != value) {
                        cfg->cpu = val;
                    }
                }

                if (strncmp(name, "TIME", strnlen(name, BUFSIZE)) == 0) {
                    int val = strtol(value, &endptr, 10);
                    if (errno || endptr != value) {
                        cfg->time = val;
                    }
                }

                if (strncmp(name, "DEADLINE_MODE", strnlen(name, BUFSIZE)) == 0) {
                    if (strncmp(value, "TRUE", strnlen(value, BUFSIZE)) == 0) {
                        cfg->use_deadline_mode = true;
                    }
                }

                if (strncmp(name, "RECEIVE_ERRORS", strnlen(name, BUFSIZE)) == 0) {
                    if (strncmp(value, "TRUE", strnlen(value, BUFSIZE)) == 0) {
                        cfg->receive_errors = true;
                    }
                }

                if (strncmp(name, "RAW_SOCKET", strnlen(name, BUFSIZE)) == 0) {
                    if (strncmp(value, "TRUE", strnlen(value, BUFSIZE)) == 0) {
                        cfg->raw_socket = true;
                    }
                }

                if (strncmp(name, "REALTIME", strnlen(name, BUFSIZE)) == 0) {
                    if (strncmp(value, "TRUE", strnlen(value, BUFSIZE)) == 0) {
                        cfg->realtime = true;
                    }
                }

                if (strncmp(name, "OFFSET", strnlen(name, BUFSIZE)) == 0) {
                    int val = strtol(value, &endptr, 10);
                    if (errno || endptr != value) {
                        cfg->offset = val;
                    }
                }

                if (strncmp(name, "PERIOD", strnlen(name, BUFSIZE)) == 0) {
                    int val = strtol(value, &endptr, 10);
                    if (errno || endptr != value) {
                        cfg->period = val;
                    }
                }

                if (strncmp(name, "IFACE", strnlen(name, BUFSIZE)) == 0) {
                    strncpy(cfg->iface, value, sizeof(cfg->iface));
                }

                if (strncmp(name, "QUEUE", strnlen(name, BUFSIZE)) == 0) {
                    int val = strtol(value, &endptr, 10);
                    if (errno || endptr != value) {
                        cfg->queue = val;
                    }
                }

                if (strncmp(name, "BPF_PROG", strnlen(name, BUFSIZE)) == 0) {
                    strncpy(cfg->bpf_prog, value, sizeof(cfg->bpf_prog));
                }

                if (strncmp(name, "DST_MAC_ADDR", strnlen(name, BUFSIZE)) == 0) {
                    sscanf(value, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &cfg->dst_mac_addr[0], &cfg->dst_mac_addr[1], &cfg->dst_mac_addr[2],
                        &cfg->dst_mac_addr[3], &cfg->dst_mac_addr[4], &cfg->dst_mac_addr[5]);
                }
            }

            memset(line, 0, BUFSIZE);
            line_idx = 0;
        }

    }

    if (close(config_file) < 0) {
        LOG_ERROR("failed to close config file: %s", strerror(errno));
    }

    return 0;
}

int get_config_string(struct config *cfg, char *buf, int size) {
    snprintf(
        buf, size, 
        "\ncfg {\n" 
        "\tiface: %s,\n"
        "\tdst_mac_addr: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx,\n"
        "\tenable_txtime: %s,\n"
        "\traw_socket: %s,\n"
        "\tperiod: %ld,\n"
        "\treceive_errors: %s\n}",
        cfg->iface,
        cfg->dst_mac_addr[0], cfg->dst_mac_addr[1], cfg->dst_mac_addr[2],
        cfg->dst_mac_addr[3], cfg->dst_mac_addr[4], cfg->dst_mac_addr[5],
        cfg->enable_txtime ? "true" : "false",
        cfg->raw_socket ? "true" : "false",
        cfg->period,
        cfg->receive_errors ? "true" : "false"
    );
    
    return 0;
}
