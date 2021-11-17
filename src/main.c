#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>

// Networking stuff
#include <arpa/inet.h> /* htons, inet_atoi, etc. */
#include <linux/ethtool.h>
#include <linux/if_packet.h> /* sockaddr_ll */
#include <linux/net_tstamp.h> /* timestamping define */
#include <sys/socket.h>

#include "common.h"
#include "config.h"
#include "connection.h"
#include "interface.h"
#include "logger.h"
#include "packet.h"
#include "utils.h"

static bool g_running = true;

void closing_handler(int signum) {
    (void)signum;

    fprintf(stderr, "\n");
    LOG_INFO("Received Ctrl+C, exiting...");
    
    g_running = false;
}

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
    (void)argc;
    (void)argv;

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

    i32 sock = open_connection(&cfg);
    if (sock < 0) {
        LOG_ERROR("Failed to open TSN socket");
        ret = -1;
        goto exit_error;
    }

    u8 src_mac_addr[6];
    get_iface_mac_address(sock, cfg.iface, src_mac_addr);

    set_realtime(getpid(), cfg.priority, cfg.cpu);

    // Get interface index from name
    int iface_index = if_nametoindex(cfg.iface);
    if (iface_index == 0) {
        LOG_ERROR("No index found for interface %s: %s", strerror(errno));
        goto clean;
    }
    LOG_TRACE("Interface '%s' has index: %d", cfg.iface, iface_index);

    // Create the sockaddr for the `sendmsg` or the `sendto`
    struct sockaddr_ll sk_addr = { 
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_8021Q),
        .sll_halen = ETH_ALEN,
        .sll_ifindex = iface_index,
    };
    memcpy(&sk_addr.sll_addr, cfg.dst_mac_addr, ETH_ALEN);

    u64 seq = 1;
    struct custom_payload *payload = (struct custom_payload*) alloca(sizeof(struct custom_payload));

    struct timespec ts;
    u64 looping_ts = get_realtime_ns() + NSEC_PER_SEC;
    u64 txtime = 0;
    setup_looping_ts_and_txtime(&ts, &looping_ts, &txtime, cfg.period, cfg.offset);

    payload->tx_queue = cfg.sk_prio;

    struct tsn_packet tsnpkt = { 0 };
    setup_tsn_packet(&tsnpkt, payload, src_mac_addr, &cfg);

    // Choose the sending semantic
    if (!cfg.enable_txtime) {
        while (g_running) {
            ret = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, NULL);
            if (ret) {
                LOG_ERROR("Failed to sleep %d: %s", ret, strerror(ret));
                break;
            }    

            u64 current_time = get_realtime_ns();

            payload->seq = seq;
            payload->tx_timestamp = current_time;

            void* offset = NULL;
            size_t packet_size = 0;
            if (cfg.raw_socket) {
                offset = (void*)&tsnpkt;
                packet_size = cfg.packet_size + 14;
            } else {
                offset = (void*)&tsnpkt.vlan_tci;
                packet_size = cfg.packet_size;
            }

            LOG_TRACE("Send packet %d: %lld", seq, txtime);

            i32 ret = sendto(sock, offset, packet_size, 0,
                 (struct sockaddr*)&sk_addr, sizeof(struct sockaddr_ll));
            if (ret < 0) {
                LOG_ERROR("sendto failed: %s", strerror(errno));
            }

            update_lopping_and_txtime(&ts, &looping_ts, &txtime, cfg.period);

            // int res = 0;
            // fd_set readfs, errorfs;
            // if (cfg.hwstamp_enabled) {
            //     struct timeval timeout;
            //     timeout.tv_usec = 2000;
            //     FD_ZERO(&readfs);
            //     FD_ZERO(&errorfs);
            //     FD_SET(sock, &readfs);
            //     FD_SET(sock, &errorfs);

            //     res = select(sock + 1, &readfs, 0, &errorfs, &timeout);
            // } else {
            //     res = 0;
            // }

            // if (res > 0) {
            //     if (FD_ISSET(sock, &errorfs)) {
            //         u64 tx_timestamp2 = extract_ts_from_cmsg(sock, MSG_ERRQUEUE);

            //         LOG_DEBUG("txtstamp: %u\t%lu\t%lu",
            //             seq - 1, txtime, tx_timestamp2);
            //     }
            // } else {
            //     // TODO(garbu): handle timeout or hwtstamp no supported?!?  
            //     LOG_WARN("txtstamp: %u\t%lu", seq - 1, txtime);
            // }

            seq += 1;
        }
    } else {
        while (g_running) {
            i32 sleep_ret = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, NULL);
            if (sleep_ret) {
                LOG_ERROR("Failed to sleep %d: %s", sleep_ret, strerror(sleep_ret));
                break;
            }    

            u64 current_time = get_realtime_ns();

            payload->seq = seq;
            payload->tx_timestamp = current_time;

            void* offset = NULL;
            size_t packet_size = 0;
            if (cfg.raw_socket) {
                offset = (void*)&tsnpkt;
                packet_size = cfg.packet_size + 14;
            } else {
                offset = (void*)&tsnpkt.vlan_tci;
                packet_size = cfg.packet_size;
            }

            LOG_TRACE("Send packet %d: %lld == %lld", seq, current_time, txtime);
       
            ret = connection_send_message(sock, offset, packet_size, txtime, &sk_addr);
            if (ret < 0) {
                LOG_ERROR("connection_send_message failed!");
            }

            update_lopping_and_txtime(&ts, &looping_ts, &txtime, cfg.period);

            seq += 1;
        }
    }

clean:
    LOG_DEBUG("cleaning stuff");
    close(sock);

exit_error:
    LOG_DEBUG("closing...");

    return ret;
}
