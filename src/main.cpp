#include <atomic>
#include <iostream>
#include <csignal>
#include <thread>

#include "sniffer/sniffer.hpp"
#include "handlers/ftp_control_handler/ftp_control_handler.hpp"
#include "handlers/ftp_data_handler/ftp_data_handler.hpp"
#include "handlers/tcp_clean_handler/tcp_clean_handler.hpp"
#include "handlers/other_handler/other_handler.hpp"

#define FTP_COMMANDS_FILE "./outfiles/ftp"
#define FTP_DATA_FILE "./outfiles/ftp_data"
#define TCP_CLEAN_FILE "./outfiles/tcp_clean"
#define OTHER_FILE "./outfiles/other"

std::atomic<bool> running = true;

void signal_handler(int signum) {
    running = false;
}


int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    
    Sniffer sniffer;
    
    std::vector<std::unique_ptr<BaseHandler>> handlers;
    
    std::cout << "Create handlers" << std::endl;

    handlers.emplace_back(
        std::make_unique<FtpControlHandler>(FTP_COMMANDS_FILE, sniffer.get_queue(FTP_CONTROL))
    );

    handlers.emplace_back(
        std::make_unique<FtpDataHandler>(FTP_DATA_FILE, sniffer.get_queue(FTP_DATA))
    );

    handlers.emplace_back(
        std::make_unique<OtherHandler>(TCP_CLEAN_FILE, sniffer.get_queue(TCP_CLEAN))
    );

    handlers.emplace_back(
        std::make_unique<OtherHandler>(OTHER_FILE, sniffer.get_queue(OTHER))
    );


    std::cout << "Start handlers" << std::endl;

    std::vector<std::thread> handler_threads;
    
    for (auto& handler : handlers) {
        handler_threads.emplace_back([&handler]() {
            handler->start();
        });
    }

    std::cout << "Start sniffer" << std::endl;

    // std::string file = "out.pcap";
    // std::string file = "big_ftp.pcap";
    // std::string file = "tcp_big_data.pcap";
    // std::string file = "test.pcap";
    std::string file = "tcp_mixed_sessions.pcap";
    std::thread sniffer_thread([&sniffer, &file]() {
        sniffer.start(FILE_MODE, file);
        running = false;
    });

    
    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));        
    }


    std::cout << "Shutting down..." << std::endl;

    sniffer.stop();

    if (sniffer_thread.joinable()) {
        sniffer_thread.join();
    }

    for (auto& thread : handler_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    for (auto& handler : handlers) {
        handler->stop();
    }

    std::cout << "Program finished" << std::endl;

    return 0;
}