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

struct packet
{
    ipheader ip;
    udpheader udp;
    dnsheader dns;
    char *dnsdata;
};

packet utils::parse_packet(const uint8_t *data)
{
    struct ipheader *ip = (struct ipheader *)data;
    struct udpheader *udp = (struct udpheader *)(data + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *)(data + sizeof(struct ipheader) + sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload
    char *dnsdata = (data + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    packet_t pckt = { *ip, *udp, *dns, dnsdata };
    return pckt;
}