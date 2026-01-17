#pragma once

#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <optional>

#include "pcap_file/packets.hpp"

#define MIN_SIZE_IP_HEADER 20
#define MIN_SIZE_TCP_HEADER 20
#define WORD_SIZE 4


class PcapFileParser {
public:
    static std::optional<PacketInfo> parse_file( u_char* packet_data, pcap_pkthdr* packet_header);
};