#if !defined(STATE_H)
#define STATE_H

#include "config.h"
#include "interface.h"

struct global_state {
	struct config cfg;
    struct interfaces *ifs;
    struct interface *current_iface;
};

i32 state__init(struct global_state *state);

i32 state__clear(struct global_state *state);

#endif // STATE_H
