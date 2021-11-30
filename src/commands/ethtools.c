#include <unistd.h>

#include <net/if.h>

#include <linux/ethtool.h>
#include <linux/sockios.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include "commands.h"
#include "interface.h"
#include "logger.h"

i32 do_ethtool_command(struct command_params *params) {
	if (params->argc == 0) {
		LOG_DEBUG("default ETHTOOL command");
		return -1;
	}
	
	if (strcmp(params->argv[0], "channels") == 0) {
		struct interface *iface = params->state->current_iface;
		if (iface) {
			i32 channels = ethtool_get_max_channels(iface->name);
			if (channels < 0) {
				LOG_ERROR("Failed to get interface %s max channels", iface->name);
			}

			fprintf(stdout, "max channels: %d\n", channels);
		}
	}	

	return 0;
}

static i32 __ethtool_get_channels(const char *ifname, i32 type) {
	i32 fd = socket(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		return -errno;
	}

	struct ethtool_channels channels = {0};
	channels.cmd = ETHTOOL_GCHANNELS;
	
	struct ifreq ifr = {0};
	ifr.ifr_data = (void*)&channels;
	memcpy(ifr.ifr_name, ifname, IF_NAMESIZE - 1);

	i32 ret = 0;
	i32 err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err && errno != EOPNOTSUPP) {
		ret = -errno;
		goto out;
	}

	if (err) {
		ret = 1;
		goto out;
	}

	u32 n_channels = 0;
	if (type == GET_CHAN_MAX) {
		n_channels = MAX(channels.max_rx, channels.max_tx);
		n_channels = MAX(n_channels, channels.max_combined);
		ret = n_channels;
		goto out;
	}
	
	if (type == GET_CHAN_CURR) {
		n_channels = MAX(channels.rx_count, channels.tx_count);
		n_channels = MAX(n_channels, channels.max_combined);
		ret = n_channels;
		goto out;
	}

out:
	close(fd);

	return ret;
}

i32 ethtool_get_max_channels(const char *ifname) {
	return __ethtool_get_channels(ifname, GET_CHAN_MAX);
}

i32 ethtool_get_channels(const char *ifname) {
	return __ethtool_get_channels(ifname, GET_CHAN_CURR);
}