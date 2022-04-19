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

bool utils::is_dns_packet(const uint8_t *data)
{
    return data[0] == 0x00 && data[1] == 0x01 && data[2] == 0x00 && data[3] == 0x01;
}