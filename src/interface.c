#include <linux/if.h>

#include <sys/ioctl.h>

#include "interface.h"
#include "logger.h"

i32 get_iface_mac_address(i32 sock, char *iface, u8* src_mac_addr) {
    struct ifreq ifr = { 0 };
    strcpy(ifr.ifr_name, iface);

    i32 res = ioctl(sock, SIOCGIFHWADDR, &ifr);
    if (res <  0) {
        LOG_ERROR("Failed to retreive the MAC address of interface %s: %s", iface, strerror(errno));
        return -1;
    }

    memcpy(src_mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    LOG_TRACE("Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
        src_mac_addr[0], src_mac_addr[1], src_mac_addr[2],
        src_mac_addr[3], src_mac_addr[4], src_mac_addr[5]);
    
    return 0;
}
