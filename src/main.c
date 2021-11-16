#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>

// Networking stuff
#include <arpa/inet.h> /* htons, inet_atoi, etc. */
#include <linux/ethtool.h>
#include <linux/if_ether.h> /* ETH_P_*, etc. */
#include <linux/if_packet.h> /* sockaddr_ll */
#include <linux/net_tstamp.h> /* timestamping define */
#include <linux/sockios.h>
#include <net/ethernet.h> /* ETHERTYPE_VLAN */
#include <net/if.h> /* netdevice interface related stuff */
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "common.h"
#include "config.h"
#include "logger.h"

static bool g_running = true;

struct __attribute__((packed)) tsn_packet {
    // Ethernet
    u8 dst_mac[6];
    u8 src_mac[6];
    // VLAN
    u16 vlan_hdr;
    u16 vlan_tci;
    // Header
    u16 eth_hdr;
    // Payload 
    void *payload;
};

struct custom_payload {
    u32 tx_queue;
    u32 seq;
    u64 tx_timestamp;
    u64 rx_timestamp;
};

void closing_handler(int signum) {
    fprintf(stderr, "\n");
    LOG_INFO("Received Ctrl+C, exiting...");
    g_running = false;
}

#define NSEC_PER_SEC 1000000000ULL

u64 get_realtime_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

int open_socket(struct config *cfg);


/* Retrieve the hardware timestamp stored in CMSG */
static uint64_t get_timestamp(struct msghdr *msg) {
	struct timespec *ts = NULL;
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET)
			continue;

		switch (cmsg->cmsg_type) {
		case SO_TIMESTAMPNS:
		case SO_TIMESTAMPING:
			ts = (struct timespec *) CMSG_DATA(cmsg);
			break;
		default: /* Ignore other cmsg options */
			break;
		}
	}

	if (!ts) {
		if (true) // TODO(garbu): set a flag for this option.
			fprintf(stderr, "Error: timestamp null. Is ptp4l initialized?\n");
		return 0;
	}

	return (ts[2].tv_sec * NSEC_PER_SEC + ts[2].tv_nsec);
}

static u64 extract_ts_from_cmsg(int sock, int recvmsg_flags) {


	u8 data[256];
	struct iovec entry;
	entry.iov_base = data;
	entry.iov_len = sizeof(data);
	
	struct sockaddr_in from_addr;
    struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &entry;
	msg.msg_iovlen = 1;
	msg.msg_name = (caddr_t)&from_addr;
	msg.msg_namelen = sizeof(from_addr);
	
    struct {
		struct cmsghdr cm;
		char control[512];
	} control;
	
    msg.msg_control = &control;
	msg.msg_controllen = sizeof(control);

	recvmsg(sock, &msg, recvmsg_flags | MSG_DONTWAIT);

	return get_timestamp(&msg);
}

int main(int argc, char *argv[]) {
    int ret = 0;

    struct config cfg = { 0 };
    if (load_config("config.cfg", &cfg) < 0) {
        LOG_ERROR("Failed to load config");
        return -1;
    }

    char buf[1024];
    get_config_string(&cfg, buf, 1024);
    
    LOG_INFO("config: %s", buf);

    signal(SIGINT, closing_handler);
    signal(SIGTERM, closing_handler);
    signal(SIGABRT, closing_handler);

    int sock = open_socket(&cfg);
    if (sock < 0) {
        LOG_ERROR("Failed to open TSN socket");
        ret = -1;
        goto exit_error;
    }

    u8 *payload = (u8*)alloca(cfg.packet_size);
    memset(payload, 0xab, cfg.packet_size);

    u8 src_mac_addr[6];

    struct ifreq ifr = { 0 };
    strcpy(ifr.ifr_name, cfg.iface);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(src_mac_addr, ifr.ifr_hwaddr.sa_data, 6);
        LOG_TRACE("Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
            src_mac_addr[0], src_mac_addr[1], src_mac_addr[2],
            src_mac_addr[3], src_mac_addr[4], src_mac_addr[5]);
    }

    if (!cfg.enable_txtime) {
        u16 vlan_tci = cfg.sk_prio << 13;
        vlan_tci |= cfg.vlan & 0x1fff;

        struct tsn_packet tsnpkt = { 0 };
        memcpy(&tsnpkt.dst_mac, cfg.dst_mac_addr, sizeof(tsnpkt.src_mac));
        memcpy(&tsnpkt.src_mac, src_mac_addr, sizeof(tsnpkt.src_mac));
        tsnpkt.vlan_hdr = htons(ETHERTYPE_VLAN);
        tsnpkt.vlan_tci = htobe16(vlan_tci);
        // tsnpkt.vlan_prio = cfg.sk_prio; // TODO(garbu): forse conviene mettere due campi diversi.
        // tsnpkt.vlan_dei = 0 << 3 & 0x1;
        // tsnpkt.vlan_id = cfg.vlan << 4 & 0xf;
        tsnpkt.eth_hdr = htons(ETH_P_TSN);
        tsnpkt.payload = payload;

        struct timespec ts;
        u64 looping_ts = get_realtime_ns();
        ts.tv_sec = (looping_ts / NSEC_PER_SEC) + 1;
        ts.tv_nsec = looping_ts % NSEC_PER_SEC;

        u8* payload_ptr = (u8 *)&tsnpkt.payload;
        struct custom_payload *payload = (struct custom_payload *)payload_ptr; 

        // u8* offset = (u8 *)&tsnpkt.vlan_prio;

        memcpy(&payload->tx_queue, &cfg.sk_prio, sizeof(u32));

        int iface_index = if_nametoindex(cfg.iface);
        if (iface_index == 0) {
            LOG_ERROR("No index found for interface %s: %s", strerror(errno));
            goto clean;
        }

        LOG_TRACE("Interface '%s' has index: %d", cfg.iface, iface_index);

        struct sockaddr_ll sk_addr = { 
            .sll_family = AF_PACKET,
            .sll_protocol = htons(ETH_P_8021Q),
            .sll_halen = ETH_ALEN,
            .sll_ifindex = iface_index,
        };

        memcpy(&sk_addr.sll_addr, cfg.dst_mac_addr, ETH_ALEN);

        u32 seq = 1;
        u64 txtime = 0;
        while (g_running) {
            ret = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, NULL);
            if (ret) {
                LOG_ERROR("Failed to sleep %d: %s", ret, strerror(ret));
                break;
            }    

            payload->seq = seq;
            txtime = get_realtime_ns();
            payload->tx_timestamp = txtime;

            LOG_TRACE("Send packet %d: %lld", seq, txtime);
            i32 ret = sendto(sock, &tsnpkt, (size_t)(cfg.packet_size + 14),
                0, (struct sockaddr*)&sk_addr, sizeof(struct sockaddr_ll));
            if (ret < 0) {
                LOG_ERROR("sendto failed: %s", strerror(errno));
            }

            looping_ts += cfg.period;
            ts.tv_sec = looping_ts / NSEC_PER_SEC;
            ts.tv_nsec = looping_ts % NSEC_PER_SEC;

            int res = 0;
            fd_set readfs, errorfs;
            if (cfg.hwstamp_enabled) {
                struct timeval timeout;
                timeout.tv_usec = 2000;
                FD_ZERO(&readfs);
                FD_ZERO(&errorfs);
                FD_SET(sock, &readfs);
                FD_SET(sock, &errorfs);

                res = select(sock + 1, &readfs, 0, &errorfs, &timeout);
            } else {
                res = 0;
            }

            if (res > 0) {
                if (FD_ISSET(sock, &errorfs)) {
                    u64 tx_timestamp2 = extract_ts_from_cmsg(sock, MSG_ERRQUEUE);

                    LOG_DEBUG("txtstamp: %u\t%lu\t%lu",
                        seq - 1, txtime, tx_timestamp2);
                }
            } else {
                // TODO(garbu): handle timeout or hwtstamp no supported?!?  
                LOG_WARN("txtstamp: %u\t%lu", seq - 1, txtime);
            }

            seq += 1;
        }

    } else {
        LOG_TRACE("TODO(garbu): handle ETF mode");
    }


clean:
    LOG_DEBUG("cleaning stuff");
    close(sock);

exit_error:
    LOG_DEBUG("closing...");

    return ret;
}

int open_socket(struct config *cfg) {
    // init the socket in AF_PACKET mode
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_8021Q));
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