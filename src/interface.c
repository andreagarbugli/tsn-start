#include <linux/net_tstamp.h>
#include <linux/sockios.h>

#include <net/if.h>

#include <sys/ioctl.h>

#include "interface.h"
#include "logger.h"

i32 interface_get_index(i32 sock, char *iface) {
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);

    i32 res = ioctl(sock, SIOCGIFINDEX, &ifr);
    if (res <  0) {
        LOG_ERROR("Failed to retreive the index of interface %s: %s", iface, strerror(errno));
        return -1;
    }

    return ifr.ifr_ifindex;
}

i32 interface_get_mac(i32 sock, char *iface, u8* src_mac_addr) {
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);

    i32 res = ioctl(sock, SIOCGIFHWADDR, &ifr);
    if (res <  0) {
        LOG_ERROR("Failed to retreive the MAC address of interface %s: %s", iface, strerror(errno));
        return -1;
    }

    memcpy(src_mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    
    return 0;
}

i32 interface_enable_hwtstamp(i32 sock, char *name) {
    struct hwtstamp_config hwconfig = {0};
    hwconfig.tx_type = HWTSTAMP_TX_ON;
    hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;

    struct ifreq ifr = {0};
    ifr.ifr_data = (void *)&hwconfig;
    strncpy(ifr.ifr_name, name, IF_NAMESIZE);

    i32 res = ioctl(sock, SIOCSHWTSTAMP, &ifr);
    if (res < 0) {
        LOG_WARN("Failed to set HWTSTAMP_TX_ON: %s", strerror(errno));
        return -1;
    }

    i32 tstamp_flags = SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
    if (
        setsockopt(
            sock, SOL_SOCKET, SO_TIMESTAMPING, 
            &tstamp_flags, sizeof(tstamp_flags)
        )
    ) {
        LOG_WARN("Failed to set socket option SO_TIMESTAMPING: %s", strerror(errno));
        return -1;
    }

    return 0;
}