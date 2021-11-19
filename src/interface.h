#if !defined(INTERFACE_H)
#define INTERFACE_H

#include "common.h"

/**
 * @brief Get the index of an interface
 * 
 * @param sock A socket file descriptor.
 * @param iface The name of the interface.
 * @return i32 - Return the index of the interface or -1 in case of errors.
 */
i32 interface_get_index(i32 sock, char *iface);

/**
 * @brief Get the MAC address of an interface.
 * 
 * @param sock A socket file descriptor.
 * @param iface The name of the interface.
 * @param src_mac_addr An array of u8 used to store the retreived address.
 * @return i32 - Return 0 if the function obtains the address, -1 in case of errors.
 */
i32 interface_get_mac(i32 sock, char *iface, u8* src_mac_addr);

i32 interface_enable_hwtstamp(i32 sock, char *name);

#endif // INTERFACE_H
