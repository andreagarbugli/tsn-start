#include <arpa/inet.h>
#include <linux/if_ether.h>

#include <net/ethernet.h>

#include "packet.h"

u8** setup_tsn_packet(u8 *buf, u8 *src_mac_addr, struct config *cfg, size_t *packet_size) {
    struct tsn_packet *pkt = (struct tsn_packet *)buf;

    u16 vlan_tci = cfg->sk_prio << 13;
    vlan_tci |= cfg->vlan & 0x1fff;

    memcpy(pkt->dst_mac, cfg->dst_mac_addr, sizeof(pkt->dst_mac));
    memcpy(pkt->src_mac, src_mac_addr, sizeof(pkt->src_mac));
    pkt->vlan_hdr = htons(ETHERTYPE_VLAN);
    pkt->vlan_tci = htobe16(vlan_tci);
    pkt->eth_hdr = htons(ETH_P_TSN);

    *packet_size = sizeof(struct tsn_packet);

    return &pkt->payload;
}