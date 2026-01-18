#include "handlers/ftp_control_handler/ftp_control_handler.hpp"


FtpControlHandler::FtpControlHandler(const std::string& output_file, SafeQueue<PacketInfo>* queue, bool txt_file) 
    : BaseHandler(output_file, queue), pcap_writer(std::make_unique<PcapFileWriter>()) {
    this->pcap_writer->open(output_file + ".pcap");
    if (txt_file)
        this->txt_file.open(output_file + ".txt");
    std::cout << "Обработчик 1 (FtpControlHandler) запустился" << std::endl;
}


FtpControlHandler::~FtpControlHandler() {
    this->pcap_writer->flush();
    this->pcap_writer->close();
    if (this->txt_file.is_open()) {
        this->txt_file.close();
    }
    std::cout << "Обработчик 1 (FtpControlHandler) завершил свою работу" << std::endl;
}


void FtpControlHandler::process_packet(const PacketInfo& packet) {
    if (txt_file)
        packet.print(this->txt_file);
    const pcap_pkthdr* header = packet.get_packet_header();
    const u_char* data = packet.get_packet_data();

    this->pcap_writer->write_packet(header, data);
}

