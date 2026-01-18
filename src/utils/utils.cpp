#include "utils/utils.hpp"


std::string utils::get_str_protocol(uint8_t proto_number) {
    switch (proto_number) {
        case IPPROTO_TCP:
            return "TCP";
         case IPPROTO_UDP:
            return "UDP";
        default:
            return "Unknown";
    }
}

std::vector<std::string> utils::split_string(const std::string& str, char del) {
    std::vector<std::string> tokens;
    std::size_t start = 0;
    std::size_t end = str.find(del);

    while (end != std::string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + 1;
        end = str.find(del, start);
    }

    tokens.push_back(str.substr(start));
    return tokens;
}


std::string utils::get_current_time(){
    auto now = std::chrono::system_clock::now();
    std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream sstream;
    sstream << std::put_time(std::localtime(&now_time_t), "%H:%M:%S");
    return sstream.str();
}

ListenerMode utils::get_mode_by_str(std::string& mode) {
    std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c) { return std::tolower(c); });
    if (mode == "file_mode") {
        return FILE_MODE;
    } else if (mode == "directory_mode") {
        return DIRECTORY_MODE;
    } else if (mode == "live_mode") {
        return LIVE_MODE;
    } else {
        return UNDEFINE;
    }
}