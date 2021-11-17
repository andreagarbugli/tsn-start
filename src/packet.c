#include <arpa/inet.h>
#include <linux/if_ether.h>

#include <net/ethernet.h>

#include "packet.h"

void setup_tsn_packet(
    struct tsn_packet *tsnpkt, void *payload,
    u8 *src_mac_addr, struct config *cfg
) {
    u16 vlan_tci = cfg->sk_prio << 13;
    vlan_tci |= cfg->vlan & 0x1fff;

    memcpy(&tsnpkt->dst_mac, cfg->dst_mac_addr, sizeof(tsnpkt->dst_mac));
    memcpy(&tsnpkt->src_mac, src_mac_addr, sizeof(tsnpkt->src_mac));
    tsnpkt->vlan_hdr = htons(ETHERTYPE_VLAN);
    tsnpkt->vlan_tci = htobe16(vlan_tci);
    tsnpkt->eth_hdr = htons(ETH_P_TSN);
    tsnpkt->payload = payload;

    u8* payload_ptr = (u8 *)&tsnpkt->payload;
}