#include <pthread.h>
#include <unistd.h> // getpid()

#include <net/if.h>

#include <linux/net_tstamp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>

#include <sys/ioctl.h>

#include "interface.h"
#include "logger.h"

void interfaces__clear(struct interfaces *ifs) {
	if (ifs) {
		if (ifs->data) {
			free(ifs->data);
			ifs->data = NULL;
		}

		free(ifs);
		ifs = NULL;
	}
}

bool interfaces__exits(struct interfaces *ifs, struct interface *iface) {
	for (size_t i = 0; i < ifs->len; i++) {
		if (strncmp(ifs->data[i].name, iface->name, IF_NAMESIZE) == 0) {
			return true;
		}
	}

	return false;
}

struct interface *interfaces__get_by_name(struct interfaces *ifs, const char *name) {
	for (size_t i = 0; i < ifs->len; i++) {
		if (strncmp(ifs->data[i].name, name, IF_NAMESIZE) == 0) {
			return &ifs->data[i];
		}
	}

	return NULL;
}

struct interface *interfaces__get_by_index(struct interfaces *ifs, i32 index) {
	for (size_t i = 0; i < ifs->len; i++) {
		if (ifs->data[i].index == index) {
			return &ifs->data[i];
		}
	}

	return NULL;
}


void interfaces__init(struct interfaces *ifs) {
	if (!ifs) {
	} else {
		ifs->data = (struct interface *)malloc(sizeof(struct interface));
		ifs->cap = 1;
		ifs->len = 0;
	}
}

i32 interfaces__push(struct interfaces *ifs, struct interface *iface) {
	if (ifs->len >= ifs->cap) {
		ifs->cap *= 2;
		
		struct interface *tmp = realloc(ifs->data, ifs->cap * sizeof(struct interface));
		if (tmp) {
			ifs->data = tmp;
		} else {
			return -1;
		}
	}

	memcpy(&ifs->data[ifs->len], iface, sizeof(struct interface));
	ifs->len += 1;

	return 0;
}

void rtnl_read_newlink(struct nlmsghdr *h, struct interfaces *ifs) {
	struct ifinfomsg *ifm = NLMSG_DATA(h);
	i32 len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));

	struct interface *iface = interfaces__get_by_index(ifs, ifm->ifi_index);
	if (!iface) {
		struct interface new_iface = {0};
		new_iface.index = ifm->ifi_index;
		
		interfaces__push(ifs, &new_iface);

		iface = interfaces__get_by_index(ifs, ifm->ifi_index);
	}

	for (
		struct rtattr *rta = IFLA_RTA(ifm);
		RTA_OK(rta, len);
		rta = RTA_NEXT(rta, len)
	) {	
		char *name = NULL;
		switch (rta->rta_type) {
			case IFLA_IFNAME:
				name = (char *)RTA_DATA(rta);
				strncpy(iface->name, name, IF_NAMESIZE - 1);
				break;
			case IFLA_LINK:
				LOG_TRACE("link = %d", *((int *)RTA_DATA(rta)));
				break;
			default:
				break;
		}
	}
}

i32 interfaces__get_all(struct interfaces *ifs) {
	i32 rtnl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (rtnl_sock < 0) {
		LOG_ERROR("Failed to open netlink socket: %s", strerror(errno));
		return -1;
	}

	pthread_t tid = pthread_self();
	pid_t pid = getpid();

	i32 nl_pid = tid << 16 | pid;
	
	struct sockaddr_nl local = {0};
	local.nl_family = AF_NETLINK;
	local.nl_pid = nl_pid;

	i32 ret = 0;
	if (bind(rtnl_sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
		goto clean;
	}

	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
		char buf[8192];
	} req = {0};
	
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_seq = 1;
	req.nlh.nlmsg_pid = nl_pid;
	req.ifm.ifi_family = AF_UNSPEC;

	struct iovec iov = {0};
	iov.iov_base = &req;
	iov.iov_len = req.nlh.nlmsg_len;

	struct sockaddr_nl kernel = {0};
	kernel.nl_family = AF_NETLINK;

	struct msghdr rtnl_msg = {0};
	rtnl_msg.msg_iov = &iov;
	rtnl_msg.msg_iovlen = 1;
	rtnl_msg.msg_name = &kernel;
	rtnl_msg.msg_namelen = sizeof(kernel);

	if (sendmsg(rtnl_sock, (struct msghdr *)&rtnl_msg, 0) < 0) {
		LOG_ERROR("Failed to sendmsg using netlink socket: %s", strerror(errno));
		ret = -1;
		goto clean;
	}

	// Receive message
	i32 done = 0;
	while (!done) {
		char recv_buf[8192]; // 8K to avoid ENOSPC
		struct iovec iov_rep = {0};
		iov_rep.iov_base = &recv_buf;
		iov_rep.iov_len = ARRAY_SIZE(recv_buf);

		struct msghdr rtnl_reply = {0};
		rtnl_reply.msg_iov = &iov_rep;
		rtnl_reply.msg_iovlen = 1;

		i32 len = recvmsg(rtnl_sock, &rtnl_reply, 0);
		if (len < 0) {
			LOG_ERROR("Failed to recvmsg from netlink socket: %s", strerror(errno));
			ret = -1;
			goto clean;
		}

		if (rtnl_reply.msg_flags & MSG_TRUNC) {
			LOG_WARN("Failed to recvmsg from netlink socket (not enough space in buf): %s", strerror(errno));
			ret = -1;
		}
			
		for (
			struct nlmsghdr *h = (struct nlmsghdr *)recv_buf;
			NLMSG_OK(h, len);
			h = NLMSG_NEXT(h, len)
		) {
			if (h->nlmsg_type == NLMSG_DONE) {
				done = 1;
				break;
			}

			if (h->nlmsg_type == NLMSG_OVERRUN) {
				LOG_DEBUG("NLMSG_OVERRUN received");
			}
			
			if (h->nlmsg_type == NLMSG_ERROR) {
				LOG_DEBUG("NLMSG_ERROR received");
				goto clean;
			}

			if (h->nlmsg_type == RTM_NEWLINK) {
				rtnl_read_newlink(h, ifs);
			}
		}
	}

clean:
	close(rtnl_sock);

	return ret;
}

i32 interface__get_index(i32 sock, char *iface) {
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);

    i32 res = ioctl(sock, SIOCGIFINDEX, &ifr);
    if (res <  0) {
        LOG_ERROR("Failed to retreive the index of interface %s: %s", iface, strerror(errno));
        return -1;
    }

    return ifr.ifr_ifindex;
}

i32 interface__get_mac(i32 sock, char *iface, u8* src_mac_addr) {
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

i32 interface__enable_hwtstamp(i32 sock, char *name) {
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
