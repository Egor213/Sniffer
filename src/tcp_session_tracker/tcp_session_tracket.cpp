#include "tcp_session_tracker/tcp_session_tracket.hpp"


void TcpSessionTracker::send_packet(PacketInfo packet) {
    if (packet.protocol != IPPROTO_TCP) {
        return;
    }

    TcpConnInfo conn;
    conn.src_ip = packet.src_ip;
    conn.src_port = packet.src_port;
    conn.dst_ip = packet.dst_ip;
    conn.dst_port = packet.dst_port;
    
    auto it = this->session_packets.find(conn);
    if (it != this->session_packets.end()) {
        const_cast<TcpConnInfo&>(it->first).update_last_use();
    }
    this->session_packets[conn].push_back(packet);
    auto& state = this->state_map[conn];

    // TODO: по-хорошему тут нужно использовать seq и ack number

    if (packet.tcp_flags & TH_SYN && !(packet.tcp_flags & TH_ACK)) {
        this->state_map[conn] = SYN_SENT_1;

    } else if (
        packet.tcp_flags & TH_SYN && 
        packet.tcp_flags & TH_ACK && 
        state == SYN_SENT_1
    ) {
        state = SYN_SENT_2;
        
    } else if (packet.tcp_flags & TH_ACK) {

        if (state == SYN_SENT_2) {
            state = ESTABLISHED;
        } else if (packet.tcp_flags & TH_FIN && state == ESTABLISHED) {
            state = FIN_SENT_1;
        } else if (state == FIN_SENT_1) {
            state = FIN_ACK_1;
        } else if (packet.tcp_flags & TH_FIN && state == FIN_ACK_1) {
            state = FIN_SENT_2;
        } else if (state == FIN_SENT_2) {
            state = CLOSED;
            this->dump_closed_session(conn);
        }
        
    } else if (packet.tcp_flags & TH_RST) {
        this->reset_session(conn);
    }
    

    // TODO: Вынести в отделный поток и запускать реже
    this->clear_stuck_sessions();
}

void TcpSessionTracker::dump_closed_session(TcpConnInfo& conn) {
    auto v = this->session_packets[conn];
    this->completed_tcp_packets.insert(this->completed_tcp_packets.end(), v.begin(), v.end());
    this->reset_session(conn);
}


void TcpSessionTracker::reset_session(TcpConnInfo& conn) {
    this->session_packets.erase(conn);
    this->state_map.erase(conn);
}


const std::vector<PacketInfo>& TcpSessionTracker::get_completed_packets() const { 
    return this->completed_tcp_packets; 
}


const std::vector<PacketInfo>& TcpSessionTracker::get_failed_packets() const { 
    return this->failed_tcp_packets; 
}


void TcpSessionTracker::clear_completed_packets() {
    this->completed_tcp_packets.clear();
}


void TcpSessionTracker::clear_stuck_sessions() {
    std::vector<TcpConnInfo> to_remove;
    
    for (auto& [conn, state] : this->state_map) {
        if (!conn.is_active()) {
            to_remove.push_back(conn);
        }
    }
    
    for (auto& conn : to_remove) {
        auto v = this->session_packets[conn];
        this->failed_tcp_packets.insert(this->failed_tcp_packets.end(), v.begin(), v.end());
        this->reset_session(conn);
    }
}

void TcpSessionTracker::dump_all_packets() {
    for (auto& [_, v] : this->session_packets) {
        this->failed_tcp_packets.insert(this->failed_tcp_packets.end(), v.begin(), v.end());
    }
    this->state_map.clear();
    this->session_packets.clear();
}