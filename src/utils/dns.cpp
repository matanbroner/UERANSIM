#include "dns.hpp"
#include "constants.hpp"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <random>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unistd.h>

// Ref: https://web.ecs.syr.edu/~wedu/seed/Labs_12.04/Networking/DNS_Remote/udp.c
// IP header's structure
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

packet dns_utils::parse_packet(const uint8_t *data)
{
    struct ipheader *ip = (struct ipheader *)data;
    struct udpheader *udp = (struct udpheader *)(data + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *)(data + sizeof(struct ipheader) + sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload
    char *dnsdata = (data + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    packet_t pckt = {*ip, *udp, *dns, dnsdata};
    return pckt;
}