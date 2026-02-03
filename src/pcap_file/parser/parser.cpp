#include "pcap_file/parser/parser.hpp"
#include <cstring> 

std::optional<PacketInfo> PcapFileParser::parse_file(u_char* packet_data_t, pcap_pkthdr* packet_header_t) {
    PacketInfo info;
    info.packet_header = *packet_header_t;
    
    info.packet_data_copy.resize(packet_header_t->caplen);
    std::memcpy(info.packet_data_copy.data(), packet_data_t, packet_header_t->caplen);

    const u_char* packet_data = info.packet_data_copy.data();
    const pcap_pkthdr* packet_header = &info.packet_header;
    
    struct ether_header* ether_header = (struct ether_header*) packet_data;
    size_t ethernet_len = sizeof(struct ether_header);

    if (ntohs(ether_header->ether_type) != ETHERTYPE_IP) {
        std::cerr << "Packet is not ETHERTYPE_IP" << std::endl;
        return std::nullopt;
    }

    struct iphdr *ip_header = (struct iphdr *)(packet_data + ethernet_len);
    size_t ip_header_len = ip_header->ihl * WORD_SIZE;

    if (ip_header_len < MIN_SIZE_IP_HEADER) {
        std::cerr << "Invalid IP header length: " << ip_header_len << " bytes" << std::endl;
        return std::nullopt;
    }

    if (ip_header->version != 4) {
        std::cerr << "Not IPv4 packet (version: " << (int)ip_header->version << ")" << std::endl;
        return std::nullopt;
    }

    info.ip_version = ip_header->version;
    info.protocol = ip_header->protocol;

    info.dst_ip = std::string(inet_ntoa(*(struct in_addr *)&ip_header->daddr));
    info.src_ip = std::string(inet_ntoa(*(struct in_addr *)&ip_header->saddr));

    if (info.protocol == IPPROTO_TCP) {
        auto total_size = ethernet_len + ip_header_len + sizeof(struct tcphdr);
        if (packet_header->len < total_size) {
            std::cerr << "Packet too small for TCP header "
                    << " packet_len: " << packet_header->len 
                    << " required: " << total_size 
                    << std::endl;
            return std::nullopt;
        }
        
        struct tcphdr *tcp_header = (struct tcphdr *)(packet_data + ethernet_len + ip_header_len);
        size_t tcp_header_len = tcp_header->doff * 4;
        
        if (tcp_header_len < MIN_SIZE_TCP_HEADER) {
            std::cerr << "TCP header is less than 20 bytes" << std::endl;
            return std::nullopt;
        }

        info.dst_port = std::to_string(ntohs(tcp_header->dest));
        info.src_port = std::to_string(ntohs(tcp_header->source));

        size_t payload_offset = ethernet_len + ip_header_len + tcp_header_len;
        size_t payload_length = packet_header->len - payload_offset;
        const u_char *payload = packet_data + payload_offset;

        info.seq_num = ntohl(tcp_header->seq);
        info.ack_num = ntohl(tcp_header->ack_seq);
        info.payload_len = payload_length;
        info.payload = payload;
        info.tcp_flags = tcp_header->th_flags;
    } else if (info.protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet_data + sizeof(struct ether_header) + ip_header_len);
        info.dst_port = std::to_string(ntohs(udp_header->dest));
        info.src_port = std::to_string(ntohs(udp_header->source));
    }
    return info;
}