#include "state.h"
#include "interface.h"

i32 state__init(struct global_state *state) {
    state->ifs = (struct interfaces *)malloc(sizeof(struct interfaces));

    interfaces__init(state->ifs);
    interfaces__get_all(state->ifs);

    state->current_iface = interfaces__get_by_name(state->ifs, state->cfg.iface);

    return 0;
}

i32 state__clear(struct global_state *state) {
    if (state->ifs) {
        interfaces__clear(state->ifs);
    }

    return 0;
}