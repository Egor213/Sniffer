#include <iostream>

#include "pcap_file/writer/writer.hpp"


PcapFileWriter::PcapFileWriter() 
    : pcap_dead_descr(nullptr), pcap_dumper(nullptr) {}


PcapFileWriter::~PcapFileWriter() {
    this->close();
}


bool PcapFileWriter::open(const std::string& file_path, int link_type, int snaplen) {
    this->pcap_dead_descr = pcap_open_dead(link_type, snaplen);

    if (!this->pcap_dead_descr) {
        std::cerr << "Failed to create pcap_dead_descr" << std::endl;
        return false;
    }

    pcap_dumper = pcap_dump_open(this->pcap_dead_descr, file_path.c_str());
        
    if (!pcap_dumper) {
        std::cerr << "Failed to open pcap file: " << pcap_geterr(this->pcap_dead_descr) << std::endl;
        pcap_close(this->pcap_dead_descr);
        this->pcap_dead_descr = nullptr;
        return false;
    }

    return true;
}


void PcapFileWriter::write_packet(pcap_pkthdr* header, u_char* data) {
    pcap_dump((u_char*)this->pcap_dumper, header, data);
}


void PcapFileWriter::flush() {
    if (this->pcap_dumper) {
        pcap_dump_flush(this->pcap_dumper);
    }
}


void PcapFileWriter::close() {
    if (this->pcap_dumper) {
        pcap_dump_close(this->pcap_dumper);
        this->pcap_dumper = nullptr;
    }
    if (this->pcap_dead_descr) {
        pcap_close(this->pcap_dead_descr);
        this->pcap_dead_descr = nullptr;
    }
}