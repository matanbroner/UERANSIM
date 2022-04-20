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

packet utils::parse_packet(const uint8_t *data)
{
    struct ipheader *ip = (struct ipheader *)data;
    struct udpheader *udp = (struct udpheader *)(data + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *)(data + sizeof(struct ipheader) + sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload
    char *dnsdata = (data + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    struct packet pckt;
    pckt.ip = *ip;
    pckt.udp = *udp;
    pckt.dns = *dns;
    pckt.dnsdata = dnsdata;

    return pckt;
}