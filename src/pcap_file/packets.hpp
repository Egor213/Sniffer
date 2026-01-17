#pragma once

#include <string>
#include <iostream>
#include <chrono>
#include <netinet/tcp.h>

#include "utils/enums.hpp"
#include "utils/utils.hpp"

#define TTL_FTP 300 

struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    std::string src_port;
    std::string dst_port;

    uint8_t protocol;
    uint8_t ip_version;
    const u_char* payload;
    size_t payload_len;

    bool finish_packet = false;
    EventType type_packet = OTHER;

    u_char* packet_data;
    pcap_pkthdr* packet_header;

    uint8_t tcp_flags = 0;

    template<typename Descr = std::ostream>
    void print(Descr& os = std::cout) const {
        os << "PacketInfo {\n";
        os << "  source_ip:  " + src_ip + ":" + src_port + "\n";
        os << "  dest_ip:  " + dst_ip + ":" + dst_port + "\n";
        os << "  protocol: " + utils::get_str_protocol(protocol) + "\n";
        os << "  IP Ver: " + std::to_string(ip_version) + "\n";
        os << "  Len:   " + std::to_string(payload_len) + " bytes\n";
        if (protocol == IPPROTO_TCP) {
            os << "  TCP Flags: " << format_tcp_flags(tcp_flags) << "\n";
        }
        os << "  Payload:  ";
        for (size_t i = 0; i < 10; ++i) {
            os << static_cast<int>(payload[i]) << " ";
        }
        if (payload_len > 10) os << "...";
        os << "\n}";
        os << std::endl;
    }

private:
    std::string format_tcp_flags(uint8_t flags) const {
        std::string result;
        if (flags & TH_FIN)  result += "FIN ";
        if (flags & TH_SYN)  result += "SYN ";
        if (flags & TH_ACK)  result += "ACK ";
        if (result.empty()) result = "NONE";
        return result;
    }
};



struct FtpConnInfo {
    FtpConnType conn_type;
    mutable std::chrono::system_clock::time_point last_use;
    std::string ip_address;
    uint16_t port;

    FtpConnInfo() : last_use(std::chrono::system_clock::now()) {}

    void update_last_use() const {
        this->last_use = std::chrono::system_clock::now();
    }

    bool is_active() const {
        auto cur = std::chrono::system_clock::now();
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(
            cur - this->last_use
        ).count();
        return diff <= TTL_FTP;
    }

    bool operator==(const FtpConnInfo& other) const {
        return this->ip_address == other.ip_address &&
               this->port == other.port;
    }

};

struct FtpConnInfoHash {
    std::size_t operator()(const FtpConnInfo& info) const {
        auto h1 = std::hash<std::string>()(info.ip_address);
        auto h2 = std::hash<uint16_t>()(info.port);
        return h1 ^ h2;
    }
};
