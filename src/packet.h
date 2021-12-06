#if !defined(PACKET_H)
#define PACKET_H

#include "common.h"
#include "config.h"

struct __attribute__((packed)) tsn_packet {
    // Ethernet
    u8 dst_mac[6];
    u8 src_mac[6];
    // VLAN
    u16 vlan_hdr;
    u16 vlan_tci;
    // Header
    u16 eth_hdr;
    // Payload
    u8 *payload;
};

typedef struct custom_payload {
    u32 tx_queue;
    u32 seq;
    u64 tx_timestamp;
    u64 rx_timestamp;
} custom_payload_t;


u8** setup_tsn_packet(u8 *buf, u8 *src_mac_addr, struct config *cfg, size_t *packet_size);

#endif // PACKET_H
