#pragma once

#include <vector>
#include <unordered_map>

#include "pcap_file/packets.hpp"

class TcpSessionTracker {
public:
    TcpSessionTracker() = default;

    void dump_all_packets();
    void send_packet(PacketInfo packet);
    const std::vector<PacketInfo>& get_completed_packets() const;
    const std::vector<PacketInfo>& get_failed_packets() const;
    void clear_completed_packets();
    
private:
    std::vector<PacketInfo> failed_tcp_packets;
    std::vector<PacketInfo> completed_tcp_packets;
    std::unordered_map<TcpConnInfo, SessionState, TcpConnInfoHash> state_map;
    std::unordered_map<TcpConnInfo, std::vector<PacketInfo>, TcpConnInfoHash> session_packets;
    
    void reset_session(TcpConnInfo& conn);
    void dump_closed_session(TcpConnInfo& conn);
    void clear_stuck_sessions();
};
