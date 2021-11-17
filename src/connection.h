#ifndef CONNECTION_H
#define CONNECTION_H

#include "config.h"

/**
 * @brief Opens a TSN connection.
 * 
 * @param cfg A reference to the configuration used by the program.
 * @return Returns a socket file descriptor.
 */
i32 open_connection(struct config *cfg);

#endif // CONNECTION_H