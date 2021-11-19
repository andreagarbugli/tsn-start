#ifndef CONNECTION_H
#define CONNECTION_H

#include <linux/if_packet.h>

#include "config.h"

struct packet_timestamps {
    struct timespec hw;
    struct timespec sw;
    struct timespec sched;
    struct timespec send;
    u8 sw_clock;
    u8 hw_clock;
};

/**
 * @brief Opens a TSN connection.
 * 
 * @param cfg A reference to the configuration used by the program.
 * @return Returns a socket file descriptor.
 */
i32 open_connection(struct config *cfg);

i32 connection_send_message(i32 sock, void *buf, size_t buffsize, 
    u64 txtime, struct sockaddr_ll *sk_addr);

i32 connection_process_socket_error_queue(i32 sock, struct packet_timestamps *pts);

i32 open_listener(struct config *cfg);

i32 listener_receive_message(i32 sock, struct config *cfg);

#endif // CONNECTION_H
