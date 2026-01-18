#pragma once

#include <iostream>
#include <fstream>
#include <memory>

#include "handlers/base_handler.hpp"
#include "pcap_file/writer/writer.hpp"


class FtpControlHandler : public BaseHandler {
public:
    FtpControlHandler(const std::string& output_file, SafeQueue<PacketInfo>* queue, bool txt_file = false);
    ~FtpControlHandler();
    
    void process_packet(const PacketInfo& packet) override;

private:
    std::unique_ptr<PcapFileWriter> pcap_writer;
    std::ofstream txt_file;
};
