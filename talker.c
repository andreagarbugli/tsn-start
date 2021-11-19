#include <poll.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>

// Networking stuff
#include <arpa/inet.h> /* htons, inet_atoi, etc. */
#include <linux/errqueue.h>
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

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    int ret = 0;

    struct config cfg = {0};
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
    interface_get_mac(sock, cfg.iface, src_mac_addr);

    int iface_index = interface_get_index(sock, cfg.iface);
    
    LOG_TRACE("Interface '%s' has index: %d", cfg.iface, iface_index);

    struct sockaddr_ll sk_addr = {0};
    sk_addr.sll_family = AF_PACKET,
    sk_addr.sll_protocol = htons(ETH_P_8021Q),
    sk_addr.sll_halen = ETH_ALEN,
    sk_addr.sll_ifindex = iface_index,
    memcpy(&sk_addr.sll_addr, cfg.dst_mac_addr, ETH_ALEN);

    if (cfg.realtime) {
        set_realtime(getpid(), cfg.priority, cfg.cpu);
    }

    u64 seq = 1;

    struct timespec ts;
    u64 looping_ts = get_realtime_ns() + NSEC_PER_SEC;
    u64 txtime = 0;
    setup_looping_ts_and_txtime(&ts, &looping_ts, &txtime, cfg.period, cfg.offset);


    u8 msg_buf[1500];

    // Choose the sending semantic
    if (!cfg.enable_txtime) {
        #if 0
        while (g_running) {
            ret = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, NULL);
            if (ret) {
                LOG_ERROR("Failed to sleep %d: %s", ret, strerror(ret));
                break;
            }    

            u64 current_time = get_realtime_ns();

            payload.seq = seq;
            payload.tx_timestamp = current_time;

            void* offset = NULL;
            size_t packet_size = 0;
            if (cfg.raw_socket) {
                offset = (void*)&pkt;
                packet_size = sizeof(struct tsn_packet) - 8
                    + sizeof(struct custom_payload);
            } else {
                offset = (void*)&pkt.vlan_tci;
                packet_size = sizeof(struct tsn_packet) - 4
                    + sizeof(struct custom_payload);
            }

            LOG_TRACE("Send packet %d: %lld", seq, txtime);

            i32 ret = sendto(sock, offset, packet_size, 0,
                 (struct sockaddr*)&sk_addr, sizeof(struct sockaddr_ll));
            if (ret < 0) {
                LOG_ERROR("sendto failed: %s", strerror(errno));
            }

            update_lopping_and_txtime(&ts, &looping_ts, &txtime, cfg.period);
            seq += 1;
        }
        #endif
    } else {
        struct pollfd pfd = {
            .fd = sock,
        };

        size_t packet_size = 0;
        u8 *offset = NULL;
        if (cfg.raw_socket) {
            offset = (u8 *) setup_tsn_packet(msg_buf, src_mac_addr, &cfg, &packet_size);
        } else {
            // packet_size = sizeof(struct custom_payload);
        }

        struct custom_payload *payload_ptr = (struct custom_payload *)offset;
        packet_size += sizeof(struct custom_payload);
        while (g_running) {
            i32 sleep_ret = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, NULL);
            if (sleep_ret) {
                LOG_WARN("Failed to sleep %d: %s", sleep_ret, strerror(sleep_ret));
                break;
            }    

            payload_ptr->tx_queue = cfg.sk_prio;
            payload_ptr->seq = seq;
       
            // LOG_TRACE("Send packet %d (size = %llu): %lld == %lld", seq, packet_size, current_time, txtime);
           
            u64 current_time = get_realtime_ns();
            payload_ptr->tx_timestamp = current_time;
            ret = connection_send_message(sock, msg_buf, packet_size, txtime, &sk_addr);
            if (ret < 0) {
                LOG_WARN("connection_send_message failed!");
            }

            update_lopping_and_txtime(&ts, &looping_ts, &txtime, cfg.period);
            seq += 1;

            usleep(100);

            // LOG_WARN("number of poll: %d", ;

            struct packet_timestamps pts = {0};

            // Check if error are pending on the error queue
            while (poll(&pfd, 1, 0) && pfd.revents & POLLERR) {
                if (connection_process_socket_error_queue(sock, &pts) < 0) {
                    LOG_DEBUG("Failed to check socket error queue");
                }
            }

            LOG_INFO(
                "(%d, %d) > usr: %llu   sched: %llu   sw: %llu   hw: %llu\n"
                "\tsw-user: %llu\tsw-sched: %llu",
                pts.sw_clock, pts.hw_clock,
                current_time, timespec_to_ns(&pts.sched), timespec_to_ns(&pts.sw), timespec_to_ns(&pts.hw),
                timespec_to_ns(&pts.sw) - current_time, timespec_to_ns(&pts.sw) - timespec_to_ns(&pts.sched)
            );
        }
    }

    LOG_DEBUG("cleaning stuff");
    close(sock);

exit_error:
    LOG_DEBUG("closing...");

    return ret;
}
