#include "tcp_session_tracker/tcp_session_tracket.hpp"

TcpSessionTracker::~TcpSessionTracker() {
    // for (auto [per, con] : this->session_packets) {
    //     std::cout << per.ip_address << ':' << per.port << ' ';
    //     for (auto a : con) {
    //         a.print();
    //     }
    // }
}

void TcpSessionTracker::send_packet(PacketInfo packet) {
    if (packet.protocol != IPPROTO_TCP) {
        return;
    }

    TcpConnInfo src_conn;
    src_conn.ip_address = packet.src_ip;
    src_conn.port = packet.src_port;

    TcpConnInfo dst_conn;
    dst_conn.ip_address = packet.dst_ip;
    dst_conn.port = packet.dst_port;

    if (this->state_map[src_conn] == ESTABLISHED) {
        this->session_packets[src_conn].push_back(packet);
    } else if (this->state_map[dst_conn] == ESTABLISHED) {
        this->session_packets[dst_conn].push_back(packet);
    }

    if (packet.tcp_flags & TH_SYN && !(packet.tcp_flags & TH_ACK)) {
        this->state_map[src_conn] = SYN_SENT;
        this->session_packets[src_conn].push_back(packet);
        
    } else if (packet.tcp_flags & TH_SYN && packet.tcp_flags & TH_ACK) {
        auto& state = this->state_map[dst_conn];
        if (state == SYN_SENT) {
            state = SYN_RECEIVED;
            this->session_packets[dst_conn].push_back(packet);
        }
        
    } else if (packet.tcp_flags & TH_ACK && !(packet.tcp_flags & TH_SYN)) {
        auto& src_state = this->state_map[src_conn];
        if (src_state == SYN_RECEIVED) {
            src_state = ESTABLISHED;
            this->session_packets[src_conn].push_back(packet);
        }
    } else if (packet.tcp_flags & TH_FIN) {
        if (this->state_map[src_conn] == ESTABLISHED) {
            this->state_map[src_conn] = FIN_WAIT_1;
            this->session_packets[src_conn].push_back(packet);
        } else if (this->state_map[dst_conn] == ESTABLISHED) {
            this->session_packets[dst_conn].push_back(packet);
        }
        
    } else if (packet.tcp_flags == TH_ACK) {
        auto& src_state = this->state_map[src_conn];
        auto& dst_state = this->state_map[dst_conn];
        
        if (src_state == FIN_WAIT_1 || src_state == CLOSING) {
            if (packet.ack_num > 0) {
                src_state = (src_state == FIN_WAIT_1) ? FIN_WAIT_2 : TIME_WAIT;
                this->session_packets[src_conn].push_back(packet);
            }
        } else if (dst_state == FIN_WAIT_1) {
            if (packet.ack_num > 0) {
                dst_state = FIN_WAIT_2;
                this->session_packets[dst_conn].push_back(packet);
            }
        }
        
    }

    this->check_connection_completion(src_conn);
    this->check_connection_completion(dst_conn);
}

void TcpSessionTracker::check_connection_completion(TcpConnInfo& conn) {
    auto state_it = this->state_map.find(conn);
    if (state_it == this->state_map.end()) {
        return;
    }

    auto& state = state_it->second;
    
    if (state == TIME_WAIT || state == CLOSED) {
        auto packets_it = this->session_packets.find(conn);
        if (packets_it != this->session_packets.end()) {
            auto& packets = packets_it->second;
            
            bool has_three_way = false;
            bool has_syn = false, has_syn_ack = false, has_ack = false;
            
            bool has_graceful_close = false;
            int fin_count = 0, ack_count = 0;
            
            for (const auto& pkt : packets) {
                if (pkt.tcp_flags == TH_SYN) has_syn = true;
                if (pkt.tcp_flags == (TH_SYN | TH_ACK)) has_syn_ack = true;
                if (pkt.tcp_flags == TH_ACK && has_syn && has_syn_ack) has_ack = true;
                
                if (pkt.tcp_flags & TH_FIN) fin_count++;
                if (pkt.tcp_flags == TH_ACK && fin_count > 0) ack_count++;
            }
            
            has_three_way = has_syn && has_syn_ack && has_ack;
            has_graceful_close = (fin_count >= 2 && ack_count >= 2);
            
            if (has_three_way && has_graceful_close) {
                for (const auto& pkt : packets) {
                    PacketInfo completed_pkt = pkt;
                    completed_pkt.type_packet = TCP_CLEAN;
                    this->completed_tcp_packets.push_back(completed_pkt);
                }
                
                this->session_packets.erase(conn);
                this->state_map.erase(conn);
            }
        }
    }
}


void TcpSessionTracker::reset_session(TcpConnInfo& conn) {
    this->session_packets.erase(conn);
    this->state_map.erase(conn);
}

const std::vector<PacketInfo>& TcpSessionTracker::get_completed_packets() const { 
    return this->completed_tcp_packets; 
}

void TcpSessionTracker::clear_completed_packets() {
    this->completed_tcp_packets.clear();
}