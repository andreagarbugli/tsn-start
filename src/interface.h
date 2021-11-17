#if !defined(INTERFACE_H)
#define INTERFACE_H

#include "common.h"

i32 get_iface_mac_address(i32 sock, char *iface, u8* src_mac_addr);

#endif // INTERFACE_H
