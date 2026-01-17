#include "handlers/ftp_data_handler/ftp_data_handler.hpp"


FtpDataHandler::FtpDataHandler(const std::string& output_file, SafeQueue<PacketInfo>* queue) 
    : BaseHandler(output_file, queue), pcap_writer(std::make_unique<PcapFileWriter>()) {
    this->pcap_writer->open(output_file + ".pcap");
    this->txt_file.open(output_file + ".txt");
}


FtpDataHandler::~FtpDataHandler() {
    this->pcap_writer->flush();
    this->pcap_writer->close();
    if (this->txt_file.is_open()) {
        this->txt_file.close();
    }
}


void FtpDataHandler::process_packet(const PacketInfo& packet) {
    packet.print(this->txt_file);
    this->pcap_writer->write_packet(packet.packet_header, packet.packet_data);
}
