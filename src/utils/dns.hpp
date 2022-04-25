//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#pragma once

#include "common_types.hpp"
#include "octet.hpp"
#include "octet_string.hpp"
#include "time_stamp.hpp"
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100

namespace utils
{
typedef struct packet packet_t;

struct ipheader
{
    unsigned char iph_ihl : 4, iph_ver : 4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    //    unsigned char      iph_flag;
    unsigned short int iph_offset;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    unsigned int iph_sourceip;
    unsigned int iph_destip;
};

// UDP header's structure
struct udpheader
{
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};

// DNS header's structure
struct dnsheader
{
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT; // Number of questions
    unsigned short int ANCOUNT; // Number of answers
    unsigned short int NSCOUNT; // Number of name server records
    unsigned short int ARCOUNT; // Number of additional records
};

// This structure just for convinience in the DNS packet, because such 4 byte data often appears.
struct dataEnd
{
    unsigned short int type;
    unsigned short int dataClass;
};

struct packet
{
    ipheader *ip;
    udpheader *udp;
    dnsheader *dns;
    const uint8_t *dnsdata;
};

packet parse_packet(const uint8_t *data)
{
    struct ipheader *ip = (struct ipheader *)data;
    struct udpheader *udp = (struct udpheader *)(data + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *)(data + sizeof(struct ipheader) + sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload
    const uint8_t *dnsdata = (data + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    packet_t pckt = {ip, udp, dns, dnsdata};
    return pckt;
}

void set_dns_server_ip(packet_t *p, const std::string &ip)
{
    struct in_addr addr;
    inet_aton(ip.c_str(), &addr);
    p->ip->iph_destip = addr.s_addr;
}

const uint8_t *packet_to_buffer(packet_t *p)
{
    return (const uint8_t *)p;
}

// General Checksum
unsigned int checksum(uint16_t *usBuff, int isize)
{
    unsigned int cksum = 0;
    for (; isize > 1; isize -= 2)
    {
        cksum += *usBuff++;
    }
    if (isize == 1)
    {
        cksum += *(uint16_t *)usBuff;
    }

    return (cksum);
}

// UDP checksum
uint16_t udp_checksum(uint8_t *buffer, int len)
{
    unsigned long sum = 0;
    struct ipheader *tempI = (struct ipheader *)(buffer);
    struct udpheader *tempH = (struct udpheader *)(buffer + sizeof(struct ipheader));
    tempH->udph_chksum = 0;
    sum = checksum((uint16_t *)&(tempI->iph_sourceip), 8);
    sum += checksum((uint16_t *)tempH, len);
    sum += ntohs(IPPROTO_UDP + len);
    sum = (sum >> 16) + (sum & 0x0000ffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static unsigned short compute_ip_checksum_util(unsigned short *addr, unsigned int count)
{
    register unsigned long sum = 0;
    while (count > 1)
    {
        sum += *addr++;
        count -= 2;
    }
    // if any bytes left, pad the bytes and add
    if (count > 0)
    {
        sum += ((*addr) & htons(0xFF00));
    }
    // Fold sum to 16 bits: add carrier to result
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // one's complement
    sum = ~sum;
    return ((unsigned short)sum);
}

void compute_ip_checksum(struct ipheader *iphdrp)
{
    iphdrp->iph_chksum = 0;
    iphdrp->iph_chksum = compute_ip_checksum_util((unsigned short *)iphdrp, iphdrp->iph_ihl << 2);
}

void apply_checksums(packet_t *p, int packetLength)
{
    compute_ip_checksum(p->ip);
    p->udp->udph_chksum = 0;
    p->udp->udph_chksum = udp_checksum((uint8_t *)p, packetLength - sizeof(struct ipheader));
}

} // namespace utils