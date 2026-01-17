#pragma once

#include <iostream>
#include <fstream>
#include <memory>

#include "handlers/base_handler.hpp"
#include "pcap_file/writer/writer.hpp"


class FtpDataHandler : public BaseHandler {
public:
    FtpDataHandler(const std::string& output_file, SafeQueue<PacketInfo>* queue);
    ~FtpDataHandler();
    
    void process_packet(const PacketInfo& packet) override;

private:
    std::unique_ptr<PcapFileWriter> pcap_writer;
    std::ofstream txt_file;
};
