#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include "utils/enums.hpp"
#include "pcap_file/reader/reader.hpp"
#include "safe_queue/safe_queue.hpp"
#include "pcap_file/packets.hpp"

struct PacketInfo;

class BaseHandler {
public:
    BaseHandler(const std::string& output_file, SafeQueue<PacketInfo>* queue);
    virtual ~BaseHandler() = default;
    void start();
    void stop();
    std::string get_output_file();
    
    virtual void process_packet(const PacketInfo& packet) = 0;

protected:
    std::string output_file;
    std::unique_ptr<PcapFileReader> pcap_file;
    SafeQueue<PacketInfo>* queue;

private:
    std::atomic<bool> running{false};
};


