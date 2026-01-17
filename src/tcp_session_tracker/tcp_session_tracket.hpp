#pragma once

#include <vector>
#include <unordered_map>

#include "pcap_file/packets.hpp"

class TcpSessionTracker {
public:
    TcpSessionTracker() = default;
    ~TcpSessionTracker();

    void send_packet(PacketInfo packet);
    const std::vector<PacketInfo>& get_completed_packets() const;
    void clear_completed_packets();
    
private:
    std::vector<PacketInfo> completed_tcp_packets;
    std::unordered_map<TcpConnInfo, SessionState, TcpConnInfoHash> state_map;
    std::unordered_map<TcpConnInfo, std::vector<PacketInfo>, TcpConnInfoHash> session_packets;
    
    void reset_session(TcpConnInfo& conn);
    void check_connection_completion(TcpConnInfo& conn);
};
