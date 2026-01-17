#include "handlers/tcp_clean_handler/tcp_clean_handler.hpp"


TcpCleanHandler::TcpCleanHandler(const std::string& output_file, SafeQueue<PacketInfo>* queue) 
    : BaseHandler(output_file, queue), pcap_writer(std::make_unique<PcapFileWriter>()) {
    this->pcap_writer->open(output_file + ".pcap");
    this->txt_file.open(output_file + ".txt");
}


TcpCleanHandler::~TcpCleanHandler() {
    this->pcap_writer->flush();
    this->pcap_writer->close();
    if (this->txt_file.is_open()) {
        this->txt_file.close();
    }
}


void TcpCleanHandler::process_packet(const PacketInfo& packet) {
    packet.print(this->txt_file);
    this->pcap_writer->write_packet(packet.packet_header, packet.packet_data);
}

