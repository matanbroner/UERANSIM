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
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};

// This structure just for convinience in the DNS packet, because such 4 byte data often appears.
struct dataEnd
{
    unsigned short int type;
    unsigned short int dataClass;
};

struct packet
{
    ipheader ip;
    udpheader udp;
    dnsheader dns;
    char *dnsdata;
};

packet parse_packet(const uint8_t *data)
{
    struct ipheader *ip = (struct ipheader *)data;
    struct udpheader *udp = (struct udpheader *)(data + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *)(data + sizeof(struct ipheader) + sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload
    char *dnsdata = ((char *)data + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    packet_t pckt = {*ip, *udp, *dns, dnsdata};
    return pckt;
}

const uint8_t* packet_to_buffer(packet_t *p){
    return reinterpret_cast<uint8_t*>p;
}

void set_dns_server_ip(packet_t *p, const std::string &ip)
{
    struct in_addr addr;
    inet_aton(ip.c_str(), &addr);
    p->ip.iph_destip = ntohl(addr.s_addr);
}

} // namespace utils