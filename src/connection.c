#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <net/if.h>

#include <linux/errqueue.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h> /* sockaddr_ll */
#include <linux/net_tstamp.h>
#include <linux/sockios.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include "connection.h"
#include "logger.h"
#include "interface.h"
#include "packet.h"
#include "utils.h"

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
        LOG_INFO("Setting TX Timestamping for interface %s", cfg->iface);
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

        int timestamping_flags = 
            SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE
            | SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_TX_SOFTWARE
            // |  SOF_TIMESTAMPING_OPT_CMSG | SOF_TIMESTAMPING_OPT_ID
            | SOF_TIMESTAMPING_TX_SCHED 
            | SOF_TIMESTAMPING_OPT_TX_SWHW
            ;
        if (setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING,
                &timestamping_flags, sizeof(timestamping_flags)) < 0) {
            LOG_ERROR("Failed to set socket options SO_TIMESTAMPING: %s", strerror(errno));
            goto clean;
        }   

        cfg->hwstamp_enabled = true;
    } else {
        LOG_WARN("Interface %s does not support HW timestamping", cfg->iface);
    }

    struct sock_txtime sk_txtime;
    sk_txtime.clockid = CLOCK_TAI,
    sk_txtime.flags = (cfg->use_deadline_mode ? SOF_TXTIME_DEADLINE_MODE : 0)
        | (cfg->receive_errors ? SOF_TXTIME_REPORT_ERRORS : 0);

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
    // u8 control[CMSG_SPACE(sizeof(u64)) + CMSG_SPACE(sizeof(u32))] = {0};

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

    // NOTE(garbu): the CMSG configuration overrides the setsockoption one
    // cmsg = CMSG_NXTHDR(&msg, cmsg);   
    // cmsg->cmsg_level = SOL_SOCKET;
    // cmsg->cmsg_type = SO_TIMESTAMPING;
    // cmsg->cmsg_len = CMSG_LEN(sizeof(u32));
    // *((u32 *) CMSG_DATA(cmsg)) = SOF_TIMESTAMPING_TX_HARDWARE;

    i32 ret = sendmsg(sock, &msg, 0);
    if (ret < 0) {
        LOG_TRACE("sendmsg failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

i32 connection_process_socket_error_queue(i32 sock, struct packet_timestamps *pts) {
    char err_buffer[1024];

    struct iovec iov;
    iov.iov_base = err_buffer;
    iov.iov_len = sizeof(err_buffer);

    // u8 control[CMSG_SPACE(sizeof(struct sock_extended_err))];
    u8 control[1024];

    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    i32 ret = recvmsg(sock, &msg, MSG_ERRQUEUE);
    if (ret < 0) {
        LOG_ERROR("recvmsg failed");
        return -1;
    }

    u64 tstamp = 0;
    struct sock_extended_err *serr = NULL;
    struct sock_extended_err *tx_serr = NULL;
    struct scm_timestamping *tss = NULL;
    for (
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg && cmsg->cmsg_len;
        cmsg = CMSG_NXTHDR(&msg, cmsg)
    ) {
        serr = (struct sock_extended_err *)CMSG_DATA(cmsg);

        if (serr->ee_origin == SO_EE_ORIGIN_TXTIME) {
            tstamp = ((u64)serr->ee_data << 32) + serr->ee_info;
            // TODO(garbu): handle other error code type???
            switch (serr->ee_code) {
                case SO_EE_CODE_TXTIME_INVALID_PARAM:
                    LOG_WARN("Packet with txtime %llu dropped due to invalid params", tstamp);
                    break;
                case SO_EE_CODE_TXTIME_MISSED:
                    LOG_WARN("Packet with txtime %llu dropped due to missed deadline", tstamp);
                    break;
                default:
                    break;
            }

            serr = NULL;
        } 
        
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING) {
			tss = (struct scm_timestamping *)CMSG_DATA(cmsg);
		} else if (cmsg->cmsg_level == SOL_PACKET && cmsg->cmsg_type == PACKET_TX_TIMESTAMP) {
			tx_serr = (struct sock_extended_err *) CMSG_DATA(cmsg);
            if (tx_serr->ee_errno == ENOMSG && tx_serr->ee_origin == SO_EE_ORIGIN_TIMESTAMPING) {
                // LOG_TRACE("received PACKET_TX_TIMESTAMP");
            } else {
                tx_serr = NULL;
            }
        }

        if (tx_serr && tss) {
            switch (tx_serr->ee_info) { // tstamp type
                case SCM_TSTAMP_SCHED:
                    if (tss->ts[0].tv_sec != 0) {
                        pts->sw_clock += 1;
                        pts->sched.tv_sec = tss->ts[0].tv_sec;
                        pts->sched.tv_nsec = tss->ts[0].tv_nsec;
                    } 
                    // NOTE(garbu): does a hw timestamp make sense for SCHED?
                    // else if (tss->ts[2].tv_sec != 0) {
                    //     pts->hw_clock += 1;
                    //     pts->hw.tv_sec = tss->ts[2].tv_sec;
                    //     pts->hw.tv_nsec = tss->ts[2].tv_nsec;
                    // }
                    break;
                case SCM_TSTAMP_SND:
                    if (tss->ts[0].tv_sec != 0) {
                        pts->sw_clock += 1;
                        pts->sw.tv_sec = tss->ts[0].tv_sec;
                        pts->sw.tv_nsec = tss->ts[0].tv_nsec;
                    } else if (tss->ts[2].tv_sec != 0) {
                        pts->hw_clock += 1;
                        pts->hw.tv_sec = tss->ts[2].tv_sec;
                        pts->hw.tv_nsec = tss->ts[2].tv_nsec;
                    }
                    break;
                case SCM_TSTAMP_ACK:
                    // NOTE(garbu): does not make sense for use (only for reliable protocols like TCP)
                    // LOG_TRACE("  ACK: %lld.%09lld", tss->ts[0].tv_sec, tss->ts[0].tv_nsec);
                    break;
                default:
                    LOG_ERROR("unknown timestamp type: %u", serr->ee_info);
                    break;
            }

            tx_serr = NULL;
            tss = NULL;
        }

        // if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING) {
        //     LOG_INFO("SO_TIMESTAMPING");
        //     struct scm_timestamping * ts = (struct scm_timestamping *)CMSG_DATA(cmsg);
        //     if (ts->ts[0].tv_sec == 0) {
        //         LOG_TRACE("  HW: %lld.%09lld", ts->ts[2].tv_sec, ts->ts[2].tv_nsec);
        //     } else {
        //         LOG_TRACE("  SW: %lld.%09lld", ts->ts[0].tv_sec, ts->ts[0].tv_nsec);
        //     }
        // }
    }

    return 0;
}

i32 open_listener(struct config *cfg) {
    i32 sock = socket(AF_PACKET, SOCK_RAW, ETH_P_8021Q);
    if (sock < 0) {
        LOG_ERROR("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    i32 iface_index = interface__get_index(sock, cfg->iface);

    // TODO(garbu): move this config somewhere.
    i32 recvbuf_size = 1500 * 10000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, &recvbuf_size, sizeof(recvbuf_size)) < 0) {
        LOG_WARN("Failed to set SO_RCVBUFFORCE option: %s", strerror(errno));
    }

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 200000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void*) &timeout, sizeof(timeout)) < 0)
    {
        LOG_ERROR("Failed to set SO_RCVTIMEO option: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_ll sk_addr = {0};
    sk_addr.sll_ifindex = iface_index;
    sk_addr.sll_family = AF_PACKET;
    sk_addr.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr*)&sk_addr, sizeof(sk_addr)) < 0) {
        LOG_ERROR("Failed to bind the RX socket to interface %s (%d): %s",
            cfg->iface, iface_index, strerror(errno));
        return -1;
    }


    struct hwtstamp_config hwconfig = {0};
    hwconfig.tx_type = 0;
    hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;
    
    struct ifreq hwtstamp_req = { 0 };
    hwtstamp_req.ifr_data = (void*)&hwconfig;
    strncpy(hwtstamp_req.ifr_name, cfg->iface, IF_NAMESIZE);

    if (ioctl(sock, SIOCSHWTSTAMP, &hwtstamp_req) < 0) {
        LOG_WARN("Failed to set HW TX timestamp: %s", strerror(errno));
    }

    i32 enable_ts = SOF_TIMESTAMPING_RX_HARDWARE 
        | SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_SOFTWARE;

    if (setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING, &enable_ts, sizeof(enable_ts)) < 0) {
        LOG_WARN("Failed to set socket option SO_TIMESTAMPING: %s", strerror(errno));
    }

    // TODO(garbu): check why we must do this.
    struct packet_mreq mreq = {0};
    mreq.mr_ifindex = iface_index;
    mreq.mr_type = PACKET_MR_PROMISC;

    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        LOG_ERROR("Failed to set socket option PACKET_ADD_MEMBERSHIP: %s", strerror(errno));
        return -1;
    }

    i32 enable_auxdata = 1;    
    if (setsockopt(sock, SOL_PACKET, PACKET_AUXDATA, &enable_auxdata, sizeof(enable_auxdata)) < 0) {
        LOG_ERROR("Failed to set socket option PACKET_AUXDATA: %s", strerror(errno));
        return -1;
    }

    interface__enable_hwtstamp(sock, cfg->iface);
    
    return sock;
}

i32 listener_receive_message(i32 sock, struct config *cfg) {
    u8 buf[1500];

    u8 control[1024];
    struct iovec iov = {0};
    iov.iov_base = &buf;
    iov.iov_len = sizeof(buf);

    struct sockaddr_ll host_address = {0};

    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = &host_address;
    msg.msg_namelen = sizeof(host_address);
    msg.msg_control = control;
    msg.msg_controllen = 128;

    i32 ret = recvmsg(sock, &msg, 0);
    i32 last_errno = errno;
    if (ret < 0) {
        switch (last_errno) {
            case EAGAIN:
                // LOG_TRACE("recvmsg TIMEDOUT");
                return 0;
            default:
                LOG_ERROR("recvmsg error %d: %s", last_errno, strerror(last_errno));
                return -1;
        }
    }

    u64 rx_timestamp = get_realtime_ns();

    struct tsn_packet *pkt = (struct tsn_packet *)buf; 
    if (memcmp(cfg->dst_mac_addr, pkt->dst_mac, ETH_ALEN) == 0) {
        // u16 vlan_tci = 0;
        // u16 vlan_tpid = 0;
        // struct timespec *hwtstamp = NULL;
        // struct scm_timestamping *ts = NULL;
        
        // for (
        //     struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        //     cmsg != NULL;
        //     cmsg = CMSG_NXTHDR(&msg, cmsg)
        // ) {
        //     if (cmsg->cmsg_level == SOL_SOCKET)
        //     {
        //         switch(cmsg->cmsg_type) 
        //         {
        //         case SO_TIMESTAMPNS:
        //             // ts = (struct timespec*) CMSG_DATA(cmsg);
        //             break;
        //         case SO_TIMESTAMPING:
        //             ts = (struct scm_timestamping *)CMSG_DATA(cmsg);
        //             // actual.swtstamp = !!ts->ts[0].tv_sec;
        //             // if (ts->ts[1].tv_sec != 0)
        //             //     error(0, 0, "ts[1] should not be set.");
	    //     		hwtstamp = &ts->ts[2];
        //             break;
        //         default:
        //             break;
        //         }
        //     }

		// 	if (cmsg->cmsg_len == CMSG_LEN(sizeof(struct tpacket_auxdata)) 
        //         || cmsg->cmsg_level == SOL_PACKET 
        //         || cmsg->cmsg_type == PACKET_AUXDATA
        //     ) {
        //         struct tpacket_auxdata *aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);
        //         vlan_tci = aux->tp_vlan_tci;
        //         vlan_tpid = aux->tp_vlan_tpid;
        //     }
        // }

        // LOG_TRACE(
        //     "%02x:%02x:%02x:%02x:%02x:%02x > %02x:%02x:%02x:%02x:%02x:%02x"
        //     " 0x%04x (802.1Q) VLAN %d PCP %d ethertype 0x%02x\t bytes %lld",
        //     pkt->src_mac[0], pkt->src_mac[1], pkt->src_mac[2], pkt->src_mac[3], pkt->src_mac[4], pkt->src_mac[5],
        //     pkt->dst_mac[0], pkt->dst_mac[1], pkt->dst_mac[2], pkt->dst_mac[3], pkt->dst_mac[4], pkt->dst_mac[5],
        //     vlan_tpid, vlan_tci & 0x1FFF, vlan_tci >> 13, ntohs(pkt->vlan_hdr),
        //     ret
        // );

        // fprintf(stderr, "\t");
        // for (int i = 0; i < ret; i += 2) {
        //     fprintf(stderr, "%02x%02x ", buf[i], buf[i + 1]);
        // }
        // fprintf(stderr, "\n");

        // u64 kts = 0;
        // if (hwtstamp) {
        //     kts = hwtstamp->tv_sec * NSEC_PER_SEC + hwtstamp->tv_nsec;
        // }

        // struct custom_payload *data_ptr = (struct custom_payload*)&pkt->vlan_tci;
        // LOG_INFO("%d - rx = %lld\tkts = %lld\ttx = %lld\t lat = %lld\t klat = %lld",
        //     data_ptr->seq, rx_timestamp, kts, data_ptr->tx_timestamp,
        //     rx_timestamp - data_ptr->tx_timestamp,
        //     rx_timestamp - kts);

        struct custom_payload *data_ptr = (struct custom_payload*)&pkt->vlan_tci;
        LOG_INFO("%d - rx = %lld\ttx = %lld\tlat = %lld",
            data_ptr->seq, rx_timestamp, data_ptr->tx_timestamp,
            rx_timestamp - data_ptr->tx_timestamp);
    }

    return 0;
}