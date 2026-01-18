#include "handlers/other_handler/other_handler.hpp"


OtherHandler::OtherHandler(const std::string& output_file, SafeQueue<PacketInfo>* queue, bool txt_file) 
    : BaseHandler(output_file, queue), pcap_writer(std::make_unique<PcapFileWriter>()) {
    this->pcap_writer->open(output_file + ".pcap");
    if (txt_file)
        this->txt_file.open(output_file + ".txt");    
    std::cout << "Обработчик 4 (OtherHandler) запустился" << std::endl;
}


OtherHandler::~OtherHandler() {
    this->pcap_writer->flush();
    this->pcap_writer->close();
    if (this->txt_file.is_open()) {
        this->txt_file.close();
    }
    std::cout << "Обработчик 4 (OtherHandler) завершил свою работу" << std::endl;
}


void OtherHandler::process_packet(const PacketInfo& packet) {
    if (packet.protocol == IPPROTO_UDP &&
        std::stoi(packet.src_port) >= 20000 &&
        std::stoi(packet.src_port) <= 25000
    ) {
        std::cout << "Обработчик 4: " << utils::get_current_time() << " пакет UDP " 
                  << packet.src_ip << ':' << packet.src_port << " -> " 
                  << packet.dst_ip << ':' << packet.dst_port << " игнорируется"
                  << std::endl;
    } else {
        if (txt_file)
            packet.print(this->txt_file);
        const pcap_pkthdr* header = packet.get_packet_header();
        const u_char* data = packet.get_packet_data();

        this->pcap_writer->write_packet(header, data);
    }
    
}

