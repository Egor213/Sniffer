#include "handlers/tcp_clean_handler/tcp_clean_handler.hpp"


TcpCleanHandler::TcpCleanHandler(const std::string& output_file, SafeQueue<PacketInfo>* queue) 
    : BaseHandler(output_file, queue), pcap_writer(std::make_unique<PcapFileWriter>()) {
    this->pcap_writer->open(output_file + ".pcap");
    this->txt_file.open(output_file + ".txt");
    std::cout << "Обработчик 3 (TcpCleanHandler) запустился" << std::endl;
}


TcpCleanHandler::~TcpCleanHandler() {
    this->pcap_writer->flush();
    this->pcap_writer->close();
    if (this->txt_file.is_open()) {
        this->txt_file.close();
    }
    std::cout << "Обработчик 3 (TcpCleanHandler) завершил свою работу" << std::endl;
}


void TcpCleanHandler::process_packet(const PacketInfo& packet) {
    packet.print(this->txt_file);
    const pcap_pkthdr* header = packet.get_packet_header();
    const u_char* data = packet.get_packet_data();

    this->pcap_writer->write_packet(header, data);
}

