#include "handlers/ftp_control_handler/ftp_control_handler.hpp"


FtpControlHandler::FtpControlHandler(const std::string& output_file, SafeQueue<PacketInfo>* queue) 
    : BaseHandler(output_file, queue), pcap_writer(std::make_unique<PcapFileWriter>()) {
    this->pcap_writer->open(output_file + ".pcap");
    this->txt_file.open(output_file + ".txt");
}


FtpControlHandler::~FtpControlHandler() {
    this->pcap_writer->flush();
    this->pcap_writer->close();
    if (this->txt_file.is_open()) {
        this->txt_file.close();
    }
}


void FtpControlHandler::process_packet(const PacketInfo& packet) {
    packet.print(this->txt_file);
    this->pcap_writer->write_packet(packet.packet_header, packet.packet_data);
}

