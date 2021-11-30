#ifndef COMMANDS_H
#define COMMANDS_H

#include "common.h"
#include "config.h"
#include "state.h"

#define COMMAND_NAME_LEN 32

struct command_params {
	struct global_state *state;
	char name[COMMAND_NAME_LEN];
	char **argv;
	i32 argc;
};

void do_command(char *cmd, i32 len, struct global_state *state);

#define GET_CHAN_MAX	1
#define GET_CHAN_CURR	2

i32 do_ethtool_command(struct command_params *params);

i32 ethtool_get_max_channels(const char *ifname);

i32 ethtool_get_channels(const char *ifname);

i32 do_interface_command(struct command_params *params);


i32 do_xdp_command(struct command_params *cp);

#endif // COMMANDS_H
