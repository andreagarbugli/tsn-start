#include <stdio.h>

#include "commands.h"
#include "interface.h"
#include "logger.h"

i32 do_interface_command(struct command_params *cp) {
	bool dump = false;
	bool refresh = false;

	if (cp->argc == 0) {
		dump = true;
	} else if (strcmp(cp->argv[0], "list") == 0) {
		dump = true;

		if (cp->argc > 1) {
			if (strcmp(cp->argv[1], "force") == 0) {
				refresh = true;
			}
		}
	}

	if (dump) {
		struct interfaces *ifs = cp->state->ifs;
		if (!ifs || refresh) {
			if (ifs) {
				interfaces__clear(ifs);
			}

			ifs = (struct interfaces *)malloc(sizeof(struct interfaces));

			interfaces__init(ifs);
			interfaces__get_all(ifs);
		}

		for (size_t i = 0; i < ifs->len; i++) {
			printf("interface { index: %d, name: %s }\n",
				   ifs->data[i].index, ifs->data[i].name);
		}
	}

	return 0;
}
