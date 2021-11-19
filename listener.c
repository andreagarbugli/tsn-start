#include <signal.h>
#include <unistd.h>

#include "config.h"
#include "connection.h"
#include "logger.h"
#include "utils.h"

static bool g_running = true;

void handler(i32 signum) {
    (void)signum;

    fprintf(stderr, "\n");
    LOG_INFO("Received a Ctrl+C, exiting...");

    g_running = false;
}

int main() {
    LOG_INFO("Start Listener Application");

    int ret = 0;

    struct config cfg = {0};
    load_config("config.cfg", &cfg);

    if (cfg.realtime) {
        set_realtime(getpid(), cfg.priority, cfg.cpu);
    }

    i32 sock = open_listener(&cfg);
    if (sock < 0) {
        LOG_ERROR("Failed to create a listener");
        ret = -1;
        goto exit_error;
    }

    while (g_running) {
        listener_receive_message(sock, &cfg);
    }

exit_error: 
    return ret;
}