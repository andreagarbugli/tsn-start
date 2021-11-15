#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>

// socket stuff
#include <sys/socket.h>
#include <linux/if_packet.h> /* sockaddr_ll */
#include <linux/if_ether.h> /* ETH_P_*, etc. */
#include <arpa/inet.h> /* htons, inet_atoi, etc. */
#include <linux/ethtool.h>
#include <sys/ioctl.h>
#include <net/if.h> /* netdevice interface related stuff */
#include <linux/net_tstamp.h> /* timestamping define */

#include "config.h"
#include "logger.h"

static bool g_running = true;

void closing_handler(int signum) {
    fprintf(stderr, "\n");
    LOG_INFO("Received Ctrl+C, exiting...");
    g_running = false;
}

int main(int argc, char *argv[]) {
    int ret = 0;

    struct config cfg = { 0 };
    if (load_config("config.cfg", &cfg) < 0) {
        LOG_ERROR("Failed to load config");
        return -1;
    }

    char buf[1024];
    get_config_string(&cfg, buf);
    
    LOG_INFO("config: %s", buf);

    signal(SIGINT, closing_handler);
    signal(SIGTERM, closing_handler);
    signal(SIGABRT, closing_handler);

    // init the socket in AF_PACKET mode
    int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_8021Q));
    if (sock < 0) {
        LOG_ERROR("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    int iface_index = if_nametoindex(cfg.iface);
    if (iface_index == 0) {
        LOG_ERROR("No index found for interface %s: %s", strerror(errno));
    }

    LOG_TRACE("Interface '%s' has index: %d", cfg.iface, iface_index);

    struct sockaddr_ll sk_addr = { 
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_8021Q),
        .sll_halen = ETH_ALEN,
        .sll_ifindex = iface_index,
    };

    memcpy(&sk_addr.sll_addr, cfg.dst_mac_addr, ETH_ALEN);

    LOG_TRACE("Setting socket options SO_PRIORITY with prio: %d", cfg.sk_prio);
    if (setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &cfg.sk_prio, sizeof(cfg.sk_prio)) < 0) {
        LOG_ERROR("Failed to set socket options SO_PRIORITY: %s", strerror(errno));
        ret = -1;
        goto clean;
    }

    LOG_TRACE("Checking hardware timestamping support for the interface %s", cfg.iface);
    struct ethtool_ts_info tsi = {
        .cmd = ETHTOOL_GET_TS_INFO
    };

    struct ifreq ethtool_req = { 0 };
    ethtool_req.ifr_data = &tsi; 
    strncpy(&ethtool_req.ifr_name, cfg.iface, IF_NAMESIZE);
    
    if (ioctl(sock, (void*)&ethtool_req) == -1) {
        LOG_ERROR("Error getting the timestamping info for interface %s: %s",
            cfg.iface, strerror(errno));
    }

    if (tsi.so_timestamping & SOF_TIMESTAMPING_RAW_HARDWARE)
        fprintf(stderr, "SOF_TIMESTAMPING_RAW_HARDWARE\t");
    if (tsi.so_timestamping & SOF_TIMESTAMPING_SYS_HARDWARE)
        fprintf(stderr, "SOF_TIMESTAMPING_SYS_HARDWARE\t");
    if (tsi.so_timestamping & SOF_TIMESTAMPING_TX_HARDWARE)
        fprintf(stderr, "SOF_TIMESTAMPING_TX_HARDWARE\t");
    if (tsi.so_timestamping & SOF_TIMESTAMPING_RX_HARDWARE)
        fprintf(stderr, "SOF_TIMESTAMPING_RX_HARDWARE\t");
    if (tsi.so_timestamping & SOF_TIMESTAMPING_TX_SOFTWARE)
        fprintf(stderr, "SOF_TIMESTAMPING_TX_SOFTWARE\t");
    if (tsi.so_timestamping & SOF_TIMESTAMPING_RX_SOFTWARE)
        fprintf(stderr, "SOF_TIMESTAMPING_RX_SOFTWARE\t");
    if (tsi.so_timestamping & SOF_TIMESTAMPING_SOFTWARE)
        fprintf(stderr, "SOF_TIMESTAMPING_SOFTWARE\t");

    while (g_running) {
        fprintf(stderr, ".");
        usleep(100000);
    }

clean:
    LOG_DEBUG("cleaning stuff");
    close(sock);

    LOG_DEBUG("closing...");

    return ret;
}
