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

packet parse_packet(const uint8_t *data);

} // namespace utils