#pragma once

#include <string>
#include <vector>
#include <pcap.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>

#include "utils/enums.hpp"

namespace utils {
    std::string get_str_protocol(uint8_t proto_number);
    std::vector<std::string> split_string(const std::string& str, char del);
    std::string get_current_time();
    ListenerMode get_mode_by_str(std::string& mode);
}