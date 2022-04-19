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
#include "~/pcapplusplus-21.11-source-linux/PcapPlusPlus/Packet++/heder/Packet.h"

namespace utils
{
bool is_dns_packet(const uint8_t *data);

#pragma pack(push, 1)
typedef struct
{
    uint16_t id; // identification number 2b

    uint8_t rd : 1;     // recursion desired
    uint8_t tc : 1;     // truncated message
    uint8_t aa : 1;     // authoritive answer
    uint8_t opcode : 4; // purpose of message
    uint8_t qr : 1;     // query/response flag

    uint8_t rcode : 4; // response code
    uint8_t cd : 1;    // checking disabled
    uint8_t ad : 1;    // authenticated data
    uint8_t z : 1;     // its z! reserved
    uint8_t ra : 1;    // recursion available 4b

    uint16_t q_count;    // number of question entries 6b
    uint16_t ans_count;  // number of answer entries 8b
    uint16_t auth_count; // number of authority entries 10b
    uint16_t add_count;  // number of resource entries 12b
} Dns_Header, *Dns_Header_P;
#pragma pack(pop)

} // namespace utils