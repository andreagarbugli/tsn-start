#if !defined(INTERFACE_H)
#define INTERFACE_H

#include <ifaddrs.h>
#include <netdb.h>

#include <linux/if_link.h>

#include <net/if.h>

#include "common.h"

struct interface {
	char name[IF_NAMESIZE];
	i32 index;
};

struct interfaces {
	struct interface *data;
	size_t len;
	size_t cap;
};

void interfaces__clear(struct interfaces *ifs);

bool interfaces__exits(struct interfaces *ifs, struct interface *iface);

struct interface *interfaces__get_by_index(struct interfaces *ifs, i32 index);

struct interface *interfaces__get_by_name(struct interfaces *ifs, const char *name);

void interfaces__init(struct interfaces *ifs);

i32 interfaces__push(struct interfaces *ifs, struct interface *iface);

i32 interfaces__get_all(struct interfaces *ifs);

/**
 * @brief Get the index of an interface
 * 
 * @param sock A socket file descriptor.
 * @param iface The name of the interface.
 * @return i32 - Return the index of the interface or -1 in case of errors.
 */
i32 interface__get_index(i32 sock, char *iface);

/**
 * @brief Get the MAC address of an interface.
 * 
 * @param sock A socket file descriptor.
 * @param iface The name of the interface.
 * @param src_mac_addr An array of u8 used to store the retreived address.
 * @return i32 - Return 0 if the function obtains the address, -1 in case of errors.
 */
i32 interface__get_mac(i32 sock, char *iface, u8* src_mac_addr);

i32 interface__enable_hwtstamp(i32 sock, char *name);

#endif // INTERFACE_H
