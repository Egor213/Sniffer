#pragma once

#include <string>
#include <pcap.h>
#include <mutex>

class PcapFileWriter {
public:
    PcapFileWriter();
    ~PcapFileWriter();
    
    bool open(const std::string& file_path, int link_type = DLT_EN10MB, int snaplen = 65535);
    void write_packet(const pcap_pkthdr* header, const u_char* data);

    void flush();
    void close();
    
private:
    pcap_t* pcap_dead_descr;
    pcap_dumper_t* pcap_dumper;
};