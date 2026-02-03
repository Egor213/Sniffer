#pragma once

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <queue>
#include <iostream>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <chrono>
#include <filesystem>
#include <algorithm>

#include "handlers/base_handler.hpp"
#include "safe_queue/safe_queue.hpp"
#include "pcap_file/reader/reader.hpp"
#include "pcap_file/parser/parser.hpp"
#include "utils/enums.hpp"
#include "utils/utils.hpp"
#include "tcp_session_tracker/tcp_session_tracket.hpp"

#define FTP_PORT 21
#define FTP_CLEANER_SLEEP 60


class Sniffer {

public:
    Sniffer();
    ~Sniffer();
    
    SafeQueue<PacketInfo>* get_queue(EventType event);
    void dispatch_packet(const PacketInfo& packet);

    void start(ListenerMode mode, const std::string& source, const std::string& filter = "tcp or udp");
    void stop();
    
private:
    std::unordered_map<EventType, std::shared_ptr<SafeQueue<PacketInfo>>> queues;
    std::unique_ptr<PcapFileReader> pcap_reader;

    std::optional<PacketInfo> process_packet(const u_char* packet_data, const pcap_pkthdr* packet_header);

    std::unordered_set<TcpConnInfo, TcpConnInfoHash> ftp_connections;

    void read_file(const std::string& file_path);
    void read_live_iface(const std::string& iface);
    std::vector<std::string> read_directory(const std::string& dir_path);
    void parse_ftp_response(const PacketInfo& info);
    void run();

    void ftp_connections_clear();
    bool running;

    std::unique_ptr<TcpSessionTracker> tcp_tracker; 
    void dump_completed_sessions();
};

