#include <thread>
#include <chrono>
#include <iostream>

#include "handlers/base_handler.hpp"


BaseHandler::BaseHandler(const std::string& output_file, SafeQueue<PacketInfo>* queue) 
    : output_file(output_file), queue(queue), pcap_file(std::make_unique<PcapFileReader>()) {}


std::string BaseHandler::get_output_file() {
    return this->output_file;
}

void BaseHandler::start() {
    this->running.store(true);
    while (this->running) {
        if (this->queue->is_empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        auto packet = this->queue->pop();

        if (packet.has_value()) {
            auto packet_value = packet.value();

            if (packet_value.finish_packet) {
                while (!this->queue->is_empty()) {
                    auto next_packet = this->queue->pop();
                    if (next_packet.has_value() && !next_packet.value().finish_packet) {
                        this->process_packet(next_packet.value());
                    }
                }
                break;
            }

            this->process_packet(packet_value);
        }
    }
}


void BaseHandler::stop() {
    this->running.store(false);
}



// ip:port SYN, SYN ACK, ACK -> FIN ACK, ACK, FIN ACK, ACK

// SYN seq numb = X
// SYN ACK seq numb = Y, ack numb = X + 1
// ACK ack numb = Y + 1

// ACK NUMBER = значение которое ожидается
