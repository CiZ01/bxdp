/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Part of the code has been taken and adapted from the Polycube project
 * (https://github.com/polycube-network/polycube) */

/* Copyright (c) 2017 The Polycube Authors */
/* Copyright (c) 2022 Sebastiano Miano <mianosebastiano@gmail.com> */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/if_vlan.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "conntrack_structs.h"
#include "conntrack_maps.h"
#include "conntrack_bpf_log.h"
#include "conntrack_parser.h"

struct t_meta
{
    unsigned short valid;
    unsigned short len1;
    unsigned short len2;
    unsigned short len3;
};

static FORCE_INLINE int track(struct packetHeaders *pkt){
    struct ct_k key;
    __builtin_memset(&key, 0, sizeof(key));
    uint8_t ipRev = 0;
    uint8_t portRev = 0;
    if (pkt->srcIp <= pkt->dstIp) {
        key.srcIp = pkt->srcIp;
        key.dstIp = pkt->dstIp;
        ipRev = 0;
    } else {
        key.srcIp = pkt->dstIp;
        key.dstIp = pkt->srcIp;
        ipRev = 1;
    }

    key.l4proto = pkt->l4proto;

    if (pkt->srcPort < pkt->dstPort) {
        key.srcPort = pkt->srcPort;
        key.dstPort = pkt->dstPort;
        portRev = 0;
    } else if (pkt->srcPort > pkt->dstPort) {
        key.srcPort = pkt->dstPort;
        key.dstPort = pkt->srcPort;
        portRev = 1;
    } else {
        key.srcPort = pkt->srcPort;
        key.dstPort = pkt->dstPort;
        portRev = ipRev;
    }

    struct ct_v newEntry;
    __builtin_memset(&newEntry, 0, sizeof(newEntry));
    struct ct_v *value;

    uint64_t timestamp;
    // timestamp = bpf_ktime_get_boot_ns();
    timestamp = bpf_ktime_get_ns();

    /* == TCP  == */
    if (pkt->l4proto == IPPROTO_TCP) {
        // If it is a RST, label it as established.
        if ((pkt->flags & TCPHDR_RST) != 0) {
            // connections.delete(&key);
            goto PASS_ACTION;
        }
        value = bpf_map_lookup_elem(&connections, &key);
        if (value != NULL) {
            // ctr_spin_lock(&value->lock);
            if ((value->ipRev == ipRev) && (value->portRev == portRev)) {
                goto TCP_FORWARD;
            } else if ((value->ipRev != ipRev) && (value->portRev != portRev)) {
                goto TCP_REVERSE;
            } else {
                // ctr_spin_unlock(&value->lock);
                goto TCP_MISS;
            }

        TCP_FORWARD:;

            // Found in forward direction
            if (value->state == SYN_SENT) {
                // Still haven't received a SYN,ACK To the SYN
                if ((pkt->flags & TCPHDR_SYN) != 0 && (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
                    // Another SYN. It is valid, probably a retransmission.
                    value->ttl = timestamp + TCP_SYN_SENT;

                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                } else {
                    // Receiving packets outside the 3-Way handshake without
                    // completing the handshake
                    bpf_log_debug("[FW_DIRECTION] Failed ACK "
                                  "check in "
                                  "SYN_SENT state. Flags: %x\n",
                                  pkt->flags);
                    pkt->connStatus = INVALID;

                    // ctr_spin_unlock(&value->lock);
                    
                    goto PASS_ACTION;
                }
            }

            if (value->state == SYN_RECV) {
                // Expecting an ACK here
                if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->flags | TCPHDR_ACK) == TCPHDR_ACK &&
                    (pkt->ackN == value->sequence)) {
                    // Valid ACK to the SYN, ACK
                    value->state = ESTABLISHED;
                    value->ttl = timestamp + TCP_ESTABLISHED;

                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "SYN_RECV to ESTABLISHED\n");

                    goto PASS_ACTION;
                } else {
                    // Validation failed, either ACK is not the only flag set or
                    // the ack number is wrong
                    pkt->connStatus = INVALID;
                    // ctr_spin_unlock(&value->lock);
                    
                    goto PASS_ACTION;
                }
            }

            if (value->state == ESTABLISHED) {
                bpf_log_debug("Connnection is ESTABLISHED\n");
                if ((pkt->flags & TCPHDR_FIN) != 0) {
                    // Received first FIN from "original" direction.
                    // Changing state to FIN_WAIT_1
                    value->state = FIN_WAIT_1;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    value->sequence = pkt->ackN;

                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "ESTABLISHED to FIN_WAIT_1. Seq: %u\n",
                                  value->sequence);

                    goto PASS_ACTION;
                } else {
                    value->ttl = timestamp + TCP_ESTABLISHED;
                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_1) {
                // Received FIN in reverse direction, waiting for ack from this
                // side
                if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->seqN == value->sequence)) {
                    // Received ACK
                    value->state = FIN_WAIT_2;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_1 to FIN_WAIT_2\n");
                    // ctr_spin_lock(&value->lock);
                } else {
                    // Validation failed, either ACK is not the only flag set or
                    // the ack number is wrong
                    pkt->connStatus = INVALID;
                    // ctr_spin_unlock(&value->lock);
                    
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_2) {
                // Already received and acked FIN in rev direction, waiting the
                // FIN from the this side
                if ((pkt->flags & TCPHDR_FIN) != 0) {
                    // FIN received. Let's wait for it to be acknowledged.
                    value->state = LAST_ACK;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    value->sequence = pkt->ackN;

                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_2 to LAST_ACK\n");

                    goto PASS_ACTION;
                } else {
                    // Still receiving packets
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
            }

            if (value->state == LAST_ACK) {
                if ((pkt->flags & TCPHDR_ACK && pkt->seqN == value->sequence) != 0) {
                    // Ack to the last FIN.
                    value->state = TIME_WAIT;
                    value->ttl = timestamp + TCP_LAST_ACK;

                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "LAST_ACK to TIME_WAIT\n");
                    goto PASS_ACTION;
                }
                // Still receiving packets
                value->ttl = timestamp + TCP_LAST_ACK;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == TIME_WAIT) {
                if (pkt->connStatus == NEW) {
                    // ctr_spin_unlock(&value->lock);
                    goto TCP_MISS;
                } else {
                    // Let the packet go, but do not update timers.
                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
            }

            // ctr_spin_unlock(&value->lock);
            bpf_log_debug("[FW_DIRECTION] Should not get here. "
                          "Flags: %x. State: %d. \n",
                          pkt->flags, value->state);
            goto PASS_ACTION;

        TCP_REVERSE:;

            // Found in reverse direction
            if (value->state == SYN_SENT) {
                // This should be a SYN, ACK answer
                if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->flags & TCPHDR_SYN) != 0 &&
                    (pkt->flags | (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK) &&
                    pkt->ackN == value->sequence) {
                    value->state = SYN_RECV;
                    value->ttl = timestamp + TCP_SYN_RECV;
                    value->sequence = pkt->seqN + HEX_BE_ONE;
                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "SYN_SENT to SYN_RECV\n");

                    goto PASS_ACTION;
                }
                // Here is an unexpected packet, only a SYN, ACK is acepted as
                // an answer to a SYN
                pkt->connStatus = INVALID;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == SYN_RECV) {
                // The only acceptable packet in SYN_RECV here is a SYN,ACK
                // retransmission
                if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->flags & TCPHDR_SYN) != 0 &&
                    (pkt->flags | (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK) &&
                    pkt->ackN == value->sequence) {
                    value->ttl = timestamp + TCP_SYN_RECV;
                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
                pkt->connStatus = INVALID;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == ESTABLISHED) {
                bpf_log_debug("Connnection is ESTABLISHED\n");
                if ((pkt->flags & TCPHDR_FIN) != 0) {
                    // Initiating closing sequence
                    value->state = FIN_WAIT_1;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    value->sequence = pkt->ackN;
                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "ESTABLISHED to FIN_WAIT_1. Seq: %x\n",
                                  value->sequence);

                    goto PASS_ACTION;
                } else {
                    value->ttl = timestamp + TCP_ESTABLISHED;
                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_1) {
                // Received FIN in reverse direction, waiting for ack from this
                // side
                if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->seqN == value->sequence)) {
                    // Received ACK
                    value->state = FIN_WAIT_2;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_1 to FIN_WAIT_2\n");
                    // ctr_spin_lock(&value->lock);

                    // Don't forward packet, we can continue performing the
                    // check in case the current packet is a ACK,FIN. In this
                    // case we match the next if statement
                } else {
                    // Validation failed, either ACK is not the only flag set or
                    // the ack number is wrong
                    pkt->connStatus = INVALID;
                    // ctr_spin_unlock(&value->lock);
                    
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_2) {
                // Already received and acked FIN in "original" direction,
                // waiting the FIN from this side
                if ((pkt->flags & TCPHDR_FIN) != 0) {
                    // FIN received. Let's wait for it to be acknowledged.
                    value->state = LAST_ACK;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    value->sequence = pkt->ackN;
                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_1 to LAST_ACK\n");

                    goto PASS_ACTION;
                } else {
                    // Still receiving packets
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    // ctr_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Failed FIN "
                                  "check in "
                                  "FIN_WAIT_2 state. Flags: %d. Seq: %d\n",
                                  pkt->flags, value->sequence);

                    goto PASS_ACTION;
                }
            }

            if (value->state == LAST_ACK) {
                if ((pkt->flags & TCPHDR_ACK && pkt->seqN == value->sequence) != 0) {
                    // Ack to the last FIN.
                    value->state = TIME_WAIT;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    // ctr_spin_unlock(&value->lock);

                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "LAST_ACK to TIME_WAIT\n");

                    goto PASS_ACTION;
                }
                // Still receiving packets
                value->ttl = timestamp + TCP_LAST_ACK;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == TIME_WAIT) {
                if (pkt->connStatus == NEW) {
                    // ctr_spin_unlock(&value->lock);
                    goto TCP_MISS;
                } else {
                    // Let the packet go, but do not update timers.
                    // ctr_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
            }

            // ctr_spin_unlock(&value->lock);
            bpf_log_debug("[REV_DIRECTION] Should not get here. "
                          "Flags: %d. "
                          "State: %d. \n",
                          pkt->flags, value->state);
            goto PASS_ACTION;
        }

    TCP_MISS:;

        // New entry. It has to be a SYN.
        if ((pkt->flags & TCPHDR_SYN) != 0 && (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
            newEntry.state = SYN_SENT;
            newEntry.ttl = timestamp + TCP_SYN_SENT;
            newEntry.sequence = pkt->seqN + HEX_BE_ONE;

            newEntry.ipRev = ipRev;
            newEntry.portRev = portRev;

            bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
            goto PASS_ACTION;
        } else {
            // Validation failed
            bpf_log_debug("Validation failed %d\n", pkt->flags);
            goto PASS_ACTION;
        }
    }

    if (pkt->l4proto == IPPROTO_UDP) {
        value = bpf_map_lookup_elem(&connections, &key);
        if (value != NULL) {
            // ctr_spin_lock(&value->lock);
            if ((value->ipRev == ipRev) && (value->portRev == portRev)) {
                goto UDP_FORWARD;
            } else if ((value->ipRev != ipRev) && (value->portRev != portRev)) {
                goto UDP_REVERSE;
            } else {
                // ctr_spin_unlock(&value->lock);
                goto UDP_MISS;
            }

        UDP_FORWARD:;

            // Valid entry
            if (value->state == NEW) {
                // An entry was already present with the NEW state. This means
                // that there has been no answer, from the other side.
                // Connection is still NEW.
                // For now I am refreshing the TTL, this can lead to an
                // DoS attack where the attacker prevents the entry from being
                // deleted by continuosly sending packets.
                value->ttl = timestamp + UDP_NEW_TIMEOUT;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            } else {
                // value->state == ESTABLISHED
                value->ttl = timestamp + UDP_ESTABLISHED_TIMEOUT;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

        UDP_REVERSE:;

            if (value->state == NEW) {
                // An entry was present in the rev direction with the NEW state.
                // This means that this is an answer, from the other side.
                // Connection is now ESTABLISHED.
                value->ttl = timestamp + UDP_NEW_TIMEOUT;
                value->state = ESTABLISHED;

                bpf_log_debug("[REV_DIRECTION] Changing state "
                              "from "
                              "NEW to ESTABLISHED\n");
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            } else {
                // value->state == ESTABLISHED
                value->ttl = timestamp + UDP_ESTABLISHED_TIMEOUT;
                // ctr_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }
        }

    UDP_MISS:;

        // No entry found in both directions. Create one.
        newEntry.ttl = timestamp + UDP_NEW_TIMEOUT;
        newEntry.state = NEW;
        newEntry.sequence = 0;

        newEntry.ipRev = ipRev;
        newEntry.portRev = portRev;

        bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
        goto PASS_ACTION;
    }

PASS_ACTION:;

    //increase pkt counter
    // struct pkt_md *md;
    // __u32 md_key = 0;
    // md = bpf_map_lookup_elem(&metadata, &md_key);
    // if (md == NULL) {
    //     bpf_log_err("No elements found in metadata map\n");
    //     goto DROP;
    // }

    // uint16_t pkt_len = (uint16_t)(data_end - data);


    // // NO_TEAR_INC(md->cnt);
    // md->cnt++;
    // // NO_TEAR_ADD(md->bytes_cnt, pkt_len);
    // md->bytes_cnt += pkt_len;

    // if (conntrack_cfg.if_index_if2 == 0) {
    //     bpf_log_err("Redirection is disabled\n");
    //     goto DROP;
    // }

    if (pkt->connStatus == INVALID) {
        bpf_log_err("Connection status is invalid\n");
    }
    //swap mac for redirection
    // data_end = (void *)(long)ctx->data_end;
    // data = (void *)(long)ctx->data;

    // if (data + ETH_HLEN > data_end) {
    //     bpf_log_err("Packet after modification is invalid! DROP\n");
    //     return -1;
    // }

    // struct ethhdr *eth = (struct ethhdr *)data;
    // eth->h_proto = bpf_htons(ETH_P_IP);

    // __builtin_memcpy(eth->h_source, (void *)conntrack_mac_cfg.if2_src_mac, sizeof(eth->h_source));
    // __builtin_memcpy(eth->h_dest, (void *)conntrack_mac_cfg.if2_dst_mac, sizeof(eth->h_dest));
    // bpf_log_debug("Redirect pkt to IF2 iface with ifindex: %d\n", conntrack_cfg.if_index_if2);

    // return bpf_redirect(conntrack_cfg.if_index_if2, 0);
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

}


SEC("xdp")
int obconntrack(struct xdp_md *ctx) {

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    void *data_meta = (void *)(long)ctx->data_meta;
    struct t_meta *md = data_meta;
    if (md + 1 > data)
    {
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

    }

    __u16 lens[4] = {bpf_ntohs(md->len1), bpf_ntohs(md->len2), bpf_ntohs(md->len3), bpf_ntohs(md->len3)};


    struct packetHeaders pkt1;
    struct packetHeaders pkt2;
    struct packetHeaders pkt3;
    struct packetHeaders pkt4;

    int ret1 = parse_packet(data, data_end, &pkt1);
    int ret2 = parse_packet(data+((lens[0])&0x1FFF), data_end, &pkt2);
    int ret3 = parse_packet(data+((lens[0]+lens[1])&0x1FFF), data_end, &pkt3);
    int ret4 = parse_packet(data+((lens[0]+lens[1]+lens[2])&0x1FFF), data_end, &pkt4);

    if (ret1 || ret2 || ret3 || ret4){
    // if (ret1 || ret2 || ret3){
    // if (ret1 || ret2){
        // bpf_printk("ret1: %d ret2: %d ret3: %d ret4:%d\n", ret1, ret2, ret3, ret4);
        bpf_printk("ret1: %d ret2: %d\n", ret1, ret2);
        bpf_printk("handle_pkt failed\n");
        return ret1;
    }

    int rc1 = track(&pkt1);
    int rc2 = track(&pkt2);
    int rc3 = track(&pkt3);
    int rc4 = track(&pkt4);

    if (rc1<0 || rc2<0 || rc3<0 || rc4<0){
    // if (rc1 <0 || rc2<0 || rc3<0){
    // if (rc1 <0 || rc2<0){

        // bpf_printk("rc1: %d rc2: %d rc3: %d rc4:%d\n", rc1, rc2, rc3, rc4);
        bpf_printk("rc1: %d rc2: %d\n", rc1, rc2);
        bpf_printk("track failed\n");
        return rc1;
    }

    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    

DROP:;
    bpf_log_err("Dropping packet!\n");
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
