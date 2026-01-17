#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "sniffer/sniffer.hpp"



Sniffer::Sniffer() {
    this->pcap_reader = std::make_unique<PcapFileReader>();
    
    this->queues[FTP_CONTROL] = std::make_shared<SafeQueue<PacketInfo>>();
    this->queues[FTP_DATA] = std::make_shared<SafeQueue<PacketInfo>>();
    this->queues[TCP_CLEAN] = std::make_shared<SafeQueue<PacketInfo>>();
    this->queues[OTHER] = std::make_shared<SafeQueue<PacketInfo>>();
}

Sniffer::~Sniffer() {
    this->stop();
}

void Sniffer::stop() {
    this->running = false;
    PacketInfo finish_packet;
    finish_packet.finish_packet = true;

    for (auto& [type, queue] : this->queues) {
        queue->push(finish_packet);
    }

    this->ftp_cv.notify_all();
    if (this->ftp_conn_cleaner_thread.joinable()) {
        this->ftp_conn_cleaner_thread.join();
    }
}

// std::optional<PacketInfo> Sniffer::process_packet(const u_char* packet_data, const pcap_pkthdr* packet_header) {
//    PacketInfo info;
//    struct ether_header* ether_header = (struct ether_header*) packet_data;
//    size_t ethernet_len = sizeof(struct ether_header);
   
//    if (ntohs(ether_header->ether_type) != ETHERTYPE_IP) {
//        return std::nullopt;
//     }
    
//     struct iphdr *ip_header = (struct iphdr *)(packet_data + ethernet_len);
//     size_t ip_header_len = ip_header->ihl * WORD_SIZE;

//     if (ip_header_len < MIN_SIZE_IP_HEADER) {
//         std::cerr << "Invalid IP header length: " << ip_header_len << " bytes" << std::endl;
//         return std::nullopt;
//     }
    
//     if (ip_header->version != 4) {
//         std::cerr << "Not IPv4 packet (version: " << (int)ip_header->version << ")" << std::endl;
//         return std::nullopt;
//     }
    
//     info.ip_version = ip_header->version;
//     info.protocol = ip_header->protocol;
    
//     info.dst_ip = std::string(inet_ntoa(*(struct in_addr *)&ip_header->daddr));
//     info.src_ip = std::string(inet_ntoa(*(struct in_addr *)&ip_header->saddr));
    
//     if (info.protocol == IPPROTO_TCP) {
//         auto total_size = ethernet_len + ip_header_len + sizeof(struct tcphdr);
//         if (packet_header->len < total_size) {
//             std::cerr << "Packet too small for TCP header "
//                       << " packet_len: " << packet_header->len 
//                       << " required: " << total_size 
//                       << std::endl;
//             return std::nullopt;
//         }
        
//         struct tcphdr *tcp_header = (struct tcphdr *)(packet_data + ethernet_len + ip_header_len);
//         size_t tcp_header_len = tcp_header->doff * 4;
        
//         if (tcp_header_len < MIN_SIZE_TCP_HEADER) {
//             std::cerr << "TCP header is less than 20 bytes" << std::endl;
//             return std::nullopt;
//         }
    
    
//         info.dst_port = std::to_string(ntohs(tcp_header->dest));
//         info.src_port = std::to_string(ntohs(tcp_header->source));


//         size_t payload_offset = ethernet_len + ip_header_len + tcp_header_len;
//         size_t payload_length = packet_header->len - payload_offset;
//         const u_char *payload = packet_data + payload_offset;

//         info.payload_len = payload_length;
//         info.payload = payload;
//         if (info.dst_port == std::to_string(FTP_PORT) || info.src_port == std::to_string(FTP_PORT)) {
//             std::string response((const char *)payload, payload_length);
//             FtpConnInfo connection_info;
//             info.type_packet = FTP_CONTROL;

//             if (response.find("227 Entering Passive Mode") != std::string::npos) {
//                 std::size_t start = response.find('(');
//                 std::size_t end = response.find(')');
//                 if (start != std::string::npos && end != std::string::npos) {
//                     auto tokens = utils::split_string(response.substr(start + 1, end - start - 1), ',');
//                     int port_high = std::stoi(tokens[tokens.size() - 2]);
//                     int port_low = std::stoi(tokens[tokens.size() - 1]);
//                     connection_info.port = port_high * 256 + port_low;
//                     connection_info.ip_address = info.src_ip;
//                     this->ftp_connections.insert(connection_info);
//                 }
//             } else if (response.find("229 Entering Extended Passive Mode") != std::string::npos) {
//                 std::size_t start = response.find('(');
//                 std::size_t end = response.find(')');
//                 if (start != std::string::npos && end != std::string::npos) {
//                     auto tokens = utils::split_string(response.substr(start + 1, end - start - 1), '|');
//                     connection_info.port = std::stoi(tokens[tokens.size() - 1]);
//                     connection_info.ip_address = info.src_ip;
//                     this->ftp_connections.insert(connection_info);
//                 }
//             } else if (response.find("PORT") == 0) {
//                 auto tokens = utils::split_string(response, ',');
//                 int port_high = std::stoi(tokens[tokens.size() - 2]);
//                 int port_low = std::stoi(tokens[tokens.size() - 1]);
//                 connection_info.port = port_high * 256 + port_low;
//                 connection_info.ip_address = info.src_ip;
//                 this->ftp_connections.insert(connection_info);
//             }
//         } else {            
//             FtpConnInfo src_conn_info;
//             src_conn_info.ip_address = info.src_ip;
//             src_conn_info.port = std::stoi(info.src_port);

//             FtpConnInfo dst_conn_info;
//             dst_conn_info.ip_address = info.dst_ip;
//             dst_conn_info.port = std::stoi(info.dst_port);


//             auto src_it = this->ftp_connections.find(src_conn_info);
//             auto dst_it = this->ftp_connections.find(dst_conn_info);

//             if (src_it != this->ftp_connections.end()) {
//                 info.type_packet = FTP_DATA;
//                 src_it->update_last_use();
//             } 
//             if (dst_it != this->ftp_connections.end()) {
//                 info.type_packet = FTP_DATA;
//                 dst_it->update_last_use();
//             }

//             // TODO: 3 обработчик
//             if (info.type_packet != FTP_DATA) {
//                 info.type_packet = OTHER;
//             }
//         }
//     }
//     info.packet_data = const_cast<u_char*>(packet_data);
//     info.packet_header = const_cast<pcap_pkthdr*>(packet_header);
//     return info;
// }




std::optional<PacketInfo> Sniffer::process_packet(const u_char* packet_data, const pcap_pkthdr* packet_header) {
    auto info_opt = PcapFileParser::parse_file(
        const_cast<u_char*>(packet_data),
        const_cast<pcap_pkthdr*>(packet_header)
    );

    if (!info_opt.has_value()) {
        return std::nullopt;
    }

    PacketInfo info = info_opt.value();
    if (info.protocol == IPPROTO_TCP) {
        if (info.dst_port == std::to_string(FTP_PORT) || info.src_port == std::to_string(FTP_PORT)) {
            info.type_packet = FTP_CONTROL;
            this->parse_ftp_response(info);
        } else {            
            FtpConnInfo src_conn_info;
            src_conn_info.ip_address = info.src_ip;
            src_conn_info.port = std::stoi(info.src_port);

            FtpConnInfo dst_conn_info;
            dst_conn_info.ip_address = info.dst_ip;
            dst_conn_info.port = std::stoi(info.dst_port);


            auto src_it = this->ftp_connections.find(src_conn_info);
            auto dst_it = this->ftp_connections.find(dst_conn_info);

            if (src_it != this->ftp_connections.end()) {
                info.type_packet = FTP_DATA;
                src_it->update_last_use();
            } 
            if (dst_it != this->ftp_connections.end()) {
                info.type_packet = FTP_DATA;
                dst_it->update_last_use();
            }

            // TODO: 3 обработчик
       
        }
    } 
    info.packet_data = const_cast<u_char*>(packet_data);
    info.packet_header = const_cast<pcap_pkthdr*>(packet_header);
    return info;
}


void Sniffer::parse_ftp_response(const PacketInfo& info) {
    FtpConnInfo connection_info;
    std::string response((const char *)info.payload, info.payload_len);
    if (response.find("227 Entering Passive Mode") != std::string::npos) {
        std::size_t start = response.find('(');
        std::size_t end = response.find(')');
        if (start != std::string::npos && end != std::string::npos) {
            auto tokens = utils::split_string(response.substr(start + 1, end - start - 1), ',');
            int port_high = std::stoi(tokens[tokens.size() - 2]);
            int port_low = std::stoi(tokens[tokens.size() - 1]);
            connection_info.port = port_high * 256 + port_low;
            connection_info.ip_address = info.src_ip;
            this->ftp_connections.insert(connection_info);
        }
    } else if (response.find("229 Entering Extended Passive Mode") != std::string::npos) {
        std::size_t start = response.find('(');
        std::size_t end = response.find(')');
        if (start != std::string::npos && end != std::string::npos) {
            auto tokens = utils::split_string(response.substr(start + 1, end - start - 1), '|');
            connection_info.port = std::stoi(tokens[tokens.size() - 1]);
            connection_info.ip_address = info.src_ip;
            this->ftp_connections.insert(connection_info);
        }
    } else if (response.find("PORT") == 0) {
        auto tokens = utils::split_string(response, ',');
        int port_high = std::stoi(tokens[tokens.size() - 2]);
        int port_low = std::stoi(tokens[tokens.size() - 1]);
        connection_info.port = port_high * 256 + port_low;
        connection_info.ip_address = info.src_ip;
        this->ftp_connections.insert(connection_info);
    }
}


void Sniffer::ftp_connections_cleaner() {
    std::vector<FtpConnInfo> to_remove;
    while (this->running) {
        std::unique_lock<std::mutex> lock(this->ftp_mutex);
        
        this->ftp_cv.wait_for(lock, std::chrono::seconds(FTP_CLEANER_SLEEP), [this] { 
            return !this->running; 
        });
    
        lock.unlock();
    
        for (const auto& it : this->ftp_connections) {
            if (!it.is_active()) {
                to_remove.push_back(it);
            }
        }

        for (const auto& el : to_remove) {
            this->ftp_connections.erase(el);
        }
        to_remove.clear();
    }
} 

void Sniffer::read_file(const std::string& file_path) {
    bool is_open = this->pcap_reader->open(file_path);
    if (!is_open) {
        std::cerr << "Error open file: " << this->pcap_reader->get_error() << std::endl;
    }
}

void Sniffer::start(ListenerMode mode, const std::string& source, const std::string& filter) {
    this->running = true;
    this->ftp_conn_cleaner_thread = std::thread(&Sniffer::ftp_connections_cleaner, this);

    switch (mode) {
        case FILE_MODE: {
            this->read_file(source);
            break;
        }
        case DIRECTORY_MODE: {
            break;
        }
        case LIVE_MODE: {
            break;
        }
        default:
            std::cerr << "Invalid mode" << std::endl;
            return;
    }
    this->pcap_reader->set_filter(filter);
    this->run();
}

void Sniffer::run() {
    while (true) {
        int res = this->pcap_reader->read_next();

        if (res == 1) {
            auto packet_data = this->pcap_reader->get_packet();
            auto packet_header = this->pcap_reader->get_packet_header();
            
            if (packet_data && packet_header) {
                auto packet = process_packet(packet_data, packet_header);
                if (packet.has_value()) {
                    this->dispatch_packet(packet.value());
                }
            }
        }
        else if (res == -1) { 
            std::cerr << "Error reading packet: " << this->pcap_reader->get_error() << std::endl;
            break;
        }
        else if (res == -2) { 
            std::cout << "End of file" << std::endl;
            break;
        }
    }
}


void Sniffer::dispatch_packet(const PacketInfo& packet) {
    auto type_event = packet.type_packet;
    if (this->queues.count(type_event)) {
        this->queues[type_event]->push(packet);
    }
}

SafeQueue<PacketInfo>* Sniffer::get_queue(EventType type) {
    return this->queues[type].get();
}

// TcpSessionTracker