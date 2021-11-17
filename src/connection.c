#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h> /* sockaddr_ll */
#include <linux/net_tstamp.h>
#include <linux/sockios.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include "connection.h"
#include "logger.h"

i32 open_connection(struct config *cfg) {
    // init the socket in AF_PACKET mode
    int sock_type = cfg->raw_socket ? SOCK_RAW : SOCK_DGRAM;
    int sock = socket(AF_PACKET, sock_type, htons(ETH_P_8021Q));
    if (sock < 0) {
        LOG_ERROR("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    LOG_TRACE("Setting socket options SO_PRIORITY with prio: %d", cfg->sk_prio);
    if (setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &cfg->sk_prio, sizeof(cfg->sk_prio)) < 0) {
        LOG_ERROR("Failed to set socket options SO_PRIORITY: %s", strerror(errno));
        goto clean;
    }

    LOG_TRACE("Checking hardware timestamping support for the interface %s", cfg->iface);
    struct ethtool_ts_info tsi = {
        .cmd = ETHTOOL_GET_TS_INFO
    };

    struct ifreq ethtool_req = { 0 };
    ethtool_req.ifr_data = (void*)&tsi; 
    strncpy(ethtool_req.ifr_name, cfg->iface, IF_NAMESIZE);
    
    if (ioctl(sock, SIOCETHTOOL, &ethtool_req) == -1) {
        LOG_ERROR("Error getting the timestamping info for interface %s: %s",
            cfg->iface, strerror(errno));
    }

    bool hwtstamp_support = false;
    if (tsi.so_timestamping & SOF_TIMESTAMPING_RAW_HARDWARE
        && tsi.so_timestamping & SOF_TIMESTAMPING_TX_HARDWARE) {
        LOG_TRACE("Interface %s supports HW timestamping", cfg->iface);
        hwtstamp_support = true;
    }

    if (hwtstamp_support) {
        struct hwtstamp_config hwconfig = { 
            .tx_type = HWTSTAMP_TX_ON,
            .rx_filter = HWTSTAMP_FILTER_ALL,
        };

        struct ifreq hwtstamp_req = { 0 };
        hwtstamp_req.ifr_data = (void*)&hwconfig;
        strncpy(hwtstamp_req.ifr_name, cfg->iface, IF_NAMESIZE);

        if (ioctl(sock, SIOCSHWTSTAMP, &hwtstamp_req) < 0) {
            LOG_ERROR("Failed to set HW TX timestamp: %s", strerror(errno));
            goto clean;
        }

        int timestamping_flags = SOF_TIMESTAMPING_TX_HARDWARE 
            | SOF_TIMESTAMPING_RAW_HARDWARE;
        if (setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING,
                &timestamping_flags, sizeof(timestamping_flags)) < 0) {
            LOG_ERROR("Failed to set socket options SO_TIMESTAMPING: %s", strerror(errno));
            goto clean;
        }   

        cfg->hwstamp_enabled = true;
    } else {
        LOG_WARN("Interface %s does not support HW timestamping", cfg->iface);
    }

    struct sock_txtime sk_txtime = {
        .clockid = CLOCK_TAI,
        .flags = (cfg->use_deadline_mode | cfg->receive_errors),
    };

    if (cfg->enable_txtime 
        && setsockopt(sock, SOL_SOCKET, SO_TXTIME, &sk_txtime, sizeof(sk_txtime)) < 0) {
        LOG_ERROR("Failed to set socket options SO_TXTIME: %s", strerror(errno));
        goto clean;
    }

    return sock;

clean:
    close(sock);
    return -1;
}

i32 connection_send_message(
    i32 sock, void *buf, size_t buffsize, 
    u64 txtime, struct sockaddr_ll *sk_addr
) {   
    struct iovec iov;
    iov.iov_base = (void*)buf;
    iov.iov_len = buffsize;

    u8 control[CMSG_SPACE(sizeof(u64))] = { 0 };

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void*)sk_addr;
    msg.msg_namelen = sizeof(struct sockaddr_ll);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_TXTIME;
    cmsg->cmsg_len = CMSG_LEN(sizeof(u64));    
    *((u64*)CMSG_DATA(cmsg)) = txtime;

    i32 ret = sendmsg(sock, &msg, 0);
    if (ret < 0) {
        LOG_ERROR("sendmsg failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}
