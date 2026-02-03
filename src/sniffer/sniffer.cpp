#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "sniffer/sniffer.hpp"


Sniffer::Sniffer() {
    this->pcap_reader = std::make_unique<PcapFileReader>();

    this->tcp_tracker = std::make_unique<TcpSessionTracker>();
    
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
}


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
        if (info.dst_port == std::to_string(FTP_PORT) || info.src_port == std::to_string(FTP_PORT)) {\
            info.type_packet = FTP_CONTROL;
            this->parse_ftp_response(info);
        } else {            
            TcpConnInfo src_conn_info;
            src_conn_info.src_ip = info.src_ip;
            src_conn_info.src_port= info.src_port;

            TcpConnInfo dst_conn_info;
            dst_conn_info.src_ip = info.dst_ip;
            dst_conn_info.src_port = info.dst_port;

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
        }
        if (info.type_packet == OTHER) {
            this->tcp_tracker->send_packet(info);
        }
    }
    return info;
}


void Sniffer::parse_ftp_response(const PacketInfo& info) {
    TcpConnInfo connection_info;
    std::string response((const char *)info.payload, info.payload_len);
    if (response.find("227 Entering Passive Mode") != std::string::npos) {
        std::size_t start = response.find('(');
        std::size_t end = response.find(')');
        if (start != std::string::npos && end != std::string::npos) {
            auto tokens = utils::split_string(response.substr(start + 1, end - start - 1), ',');
            int port_high = std::stoi(tokens[tokens.size() - 2]);
            int port_low = std::stoi(tokens[tokens.size() - 1]);
            connection_info.src_port = std::to_string(port_high * 256 + port_low);
            connection_info.src_ip = info.src_ip;
            this->ftp_connections.insert(connection_info);
        }
    } else if (response.find("229 Entering Extended Passive Mode") != std::string::npos) {
        std::size_t start = response.find('(');
        std::size_t end = response.find(')');
        if (start != std::string::npos && end != std::string::npos) {
            auto tokens = utils::split_string(response.substr(start + 1, end - start - 1), '|');
            connection_info.src_port = tokens[tokens.size() - 1];
            connection_info.src_ip = info.src_ip;
            this->ftp_connections.insert(connection_info);
        }
    } else if (response.find("PORT") == 0) {
        auto tokens = utils::split_string(response, ',');
        int port_high = std::stoi(tokens[tokens.size() - 2]);
        int port_low = std::stoi(tokens[tokens.size() - 1]);
        connection_info.src_port = std::to_string(port_high * 256 + port_low);
        connection_info.src_ip = info.src_ip;
        this->ftp_connections.insert(connection_info);
    }
}


void Sniffer::  ftp_connections_clear() {
    std::vector<TcpConnInfo> to_remove;

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


void Sniffer::read_file(const std::string& file_path) {
    namespace fs = std::filesystem;

    if (!fs::exists(file_path)) {
        throw std::runtime_error("File not found");
    }

    bool is_open = this->pcap_reader->open(file_path);
    if (!is_open) {
        throw std::runtime_error("Path is not a directory or does not exist: " +  this->pcap_reader->get_error());
    }
}


void Sniffer::read_live_iface(const std::string& iface) {
    bool is_open = this->pcap_reader->open(iface, true);
    if (!is_open) {
        throw std::runtime_error("Interface does not exist: " +  this->pcap_reader->get_error());
    }
}


std::vector<std::string> Sniffer::read_directory(const std::string& dir_path) {
    namespace fs = std::filesystem;
    
    try {
        if (!fs::exists(dir_path) || !fs::is_directory(dir_path)) {
            throw std::runtime_error("Path is not a directory or does not exist: " + dir_path);
        }
        
        std::vector<std::string> pcap_files;
        for (const auto& entry : fs::directory_iterator(dir_path)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext == ".pcap") {
                    pcap_files.push_back(entry.path().string());
                }
            }
        }        
        return pcap_files;
        
    } catch (const std::exception& e) {
        std::cerr << "Directory processing error: " << e.what() << std::endl;
    }
    return std::vector<std::string>{};
}


void Sniffer::start(ListenerMode mode, const std::string& source, const std::string& filter) {
    this->running = true;

    switch (mode) {
        case FILE_MODE: {
            this->read_file(source);
            this->pcap_reader->set_filter(filter);
            this->run();
            break;
        }
        case DIRECTORY_MODE: {
            auto files = this->read_directory(source);
            for (auto& file : files) {
                this->read_file(file);
                this->pcap_reader->set_filter(filter);
                this->run();
            }
            break;
        }
        case LIVE_MODE: {
            this->read_live_iface(source);
            this->pcap_reader->set_filter(filter);
            this->run();
            break;
        }
        default:
            std::cerr << "Invalid mode" << std::endl;
            return;
    }
}


void Sniffer::run() {
    int cnt = 0;
    while (this->running) {
        int res = this->pcap_reader->read_next();

        if (res == 1) {
            auto packet_data = this->pcap_reader->get_packet();
            auto packet_header = this->pcap_reader->get_packet_header();
            if (packet_data && packet_header) {
                auto packet = process_packet(packet_data, packet_header);
                this->dump_completed_sessions();
                if (packet.has_value() && packet.value().type_packet != OTHER) {
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
        if (++cnt % 100 == 0) {
            this->ftp_connections_clear();
            cnt = 0;
        }
    }
    this->tcp_tracker->dump_all_packets();
    for (auto& packet : this->tcp_tracker->get_failed_packets()) {
        this->dispatch_packet(packet);
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


void Sniffer::dump_completed_sessions() {
    for (PacketInfo completed_packet : this->tcp_tracker->get_completed_packets()){
        completed_packet.type_packet = TCP_CLEAN;
        this->dispatch_packet(completed_packet);
    }
    this->tcp_tracker->clear_completed_packets();
}