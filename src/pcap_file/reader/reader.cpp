#include <iostream>
#include "pcap_file/reader/reader.hpp"


PcapFileReader::PcapFileReader() 
    : handle(nullptr), current_header(nullptr), current_packet(nullptr) {}


PcapFileReader::~PcapFileReader() {
    close();
}

void PcapFileReader::close() {

    std::lock_guard<std::recursive_mutex> lock(this->mutex);

    if (this->handle) {
        pcap_close(this->handle);
        this->handle = nullptr;
    }

    this->current_header = nullptr;
    this->current_packet = nullptr;
    this->error.clear();
}

bool PcapFileReader::open(const std::string& file_path) {

    std::lock_guard<std::recursive_mutex> lock(this->mutex);

    this->close();

    char errbuf[PCAP_ERRBUF_SIZE];
    
    this->handle = pcap_open_offline(file_path.c_str(), errbuf);

    if (this->handle == nullptr) {
        this->error = errbuf;
        return false;
    }

    this->error.clear();
    return true;
}


const int PcapFileReader::read_next() {
    std::lock_guard lock(this->mutex);
    return pcap_next_ex(this->handle, &this->current_header, &this->current_packet);
}


const struct pcap_pkthdr* PcapFileReader::get_packet_header() {
    return this->current_packet ? this->current_header : nullptr;
}


const u_char* PcapFileReader::get_packet() {
    return this->current_packet ? this->current_packet : nullptr;
}


bool PcapFileReader::is_open() {
    return this->handle != nullptr;
}


std::string PcapFileReader::get_error() {
    return this->error;
}


void PcapFileReader::set_filter(const std::string& filter) {
    struct bpf_program fp;
    if (pcap_compile(this->handle, &fp, filter.c_str(), 0, 0) == -1) {
        std::cerr << "Error complite filter: " << pcap_geterr(this->handle) << std::endl;
        return;
    }
    if (pcap_setfilter(this->handle, &fp) == -1) {
        std::cerr << "Error setup filter: " << pcap_geterr(this->handle) << std::endl;
        return;
    }
}
