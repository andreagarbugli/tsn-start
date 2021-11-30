#include <ctype.h>

#include "commands.h"
#include "logger.h"
#include "interface.h"

extern bool g_running;

i32 do_clear_command(struct command_params *cp) {
	(void)cp;
	printf("\e[1;1H\e[2J");	
	return 0;
}

i32 do_quit_command(struct command_params *cp) {
	(void)cp;
	g_running = false;
	return 0;
}

i32 do_state_command(struct command_params *cp) {
	struct global_state *s = cp->state;

	printf("GLOBAL STATE\n");
	struct interfaces *ifs = s->ifs;
	if (ifs) {
		printf("\tother ifaces:\n");
		struct interface *iface = NULL; 
		for (size_t i = 0; i < ifs->len; ++i) {
			iface = &ifs->data[i];
			printf("\t\t(%d) %s\n", iface->index, iface->name);
		}
	}

	if (s->current_iface) {
		printf("\tcurrent iface: %s (%d)\n", s->current_iface->name, s->current_iface->index);
	}

	return 0;
}

static const struct command {
	char *name;
	i32 (*exec)(struct command_params *params);
} commands[] = {
	{ "clear", do_clear_command },
	{ "eth", do_ethtool_command },
	{ "iface", do_interface_command },
	{ "quit", do_quit_command },
	{ "state", do_state_command },
	{ "xdp", do_xdp_command },
	{ 0 }
};

i32 __parse_command(char *cmd, size_t len, struct command_params *cp) {
	cp->argc = 0;
	cp->argv = NULL;

	i32 j = 0;
	for (size_t i = 0; i <= len; ++i) {
		char c = cmd[i];
		if (isspace(c) && j > 0) {
			cp->argc += 1;
			j = 0;
		} else {
			j += 1;
		}	
	}
	
	// if j is still greater than 0, means that we didn't count
	// the last argument
	if (j > 0) {
		cp->argc += 1;
		j = 0;
	}

	// Remove the command name
	cp->argc -= 1; 

	if (cp->argc > 0) {
		cp->argv = malloc(sizeof(char *) * cp->argc);
	} 

	bool name_found = false;
	char buf[128] = {0};
	i32 k = 0;
	for (size_t i = 0; i <= len; i++) {
		char c = cmd[i];
		if (isspace(c) && j > 0) {
			if (!name_found) {
				strncpy(cp->name, buf, COMMAND_NAME_LEN - 1);
				name_found = true;
			} else {
				cp->argv[k] = calloc(j + 1, sizeof(char));
				strncpy(cp->argv[k], buf, j);
				k += 1;
			}

			memset(buf, 0, sizeof(buf));
			j = 0;
		} else {
			buf[j] = c;
			j += 1;
		}	
	}

	buf[j] = '\0';
	if (j > 0 && !name_found) {
		strncpy(cp->name, buf, COMMAND_NAME_LEN - 1);
	} else if (j > 0) {
		cp->argv[k] = calloc(j + 1, sizeof(char));
		strncpy(cp->argv[k], buf, j);
	}

	return 0;
}

void __clear_params(struct command_params *cp) {
	if (cp->argv) {
		for (i32 i = 0; i < cp->argc; ++i) {
			free(cp->argv[i]);
			cp->argv[i] = NULL;
		}

		free(cp->argv);
		cp->argv = NULL;
		cp->argc = 0;
	}

	memset(cp->name, 0, COMMAND_NAME_LEN);
}

void do_command(char *cmd, i32 len, struct global_state *state) {	
	struct command_params params = {0};
	__parse_command(cmd, len, &params);
	params.state = state;

	const struct command *c;
	for (c = commands; c->name; ++c) {
		if (strncmp(c->name, params.name, COMMAND_NAME_LEN - 1) == 0)  {
			c->exec(&params);
			goto clean;
		}
	}

	printf("no command found: %s", params.name);

clean:
	__clear_params(&params);
}
