#pragma once

#include <string>
#include <pcap.h>
#include <mutex>

class PcapFileReader {
public:
    PcapFileReader();
    ~PcapFileReader();
    
    bool open(const std::string& source, bool is_live = false);
    void close();
    
    const int read_next();

    void set_filter(const std::string& filter);
    
    const struct pcap_pkthdr* get_packet_header();
    const u_char* get_packet();
    bool is_open();
    
    std::string get_error();
    
private:
    pcap_t* handle;
    std::string error;
    std::recursive_mutex mutex;

    struct pcap_pkthdr* current_header;
    const u_char* current_packet;
};