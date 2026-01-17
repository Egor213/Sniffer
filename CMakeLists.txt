cmake_minimum_required(VERSION 3.15)

project(sniffer VERSION 1.0 LANGUAGES CXX)

set(SOURCE_EXE src/main.cpp)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(LIBPCAP_LIBRARY ${CMAKE_SOURCE_DIR}/libs/libpcap/libpcap.so.1.10.5)

include_directories(${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/libs/include)

add_executable(main ${SOURCE_EXE})

target_sources(main PRIVATE
    src/sniffer/sniffer.cpp
    src/utils/utils.cpp
    src/pcap_file/reader/reader.cpp
    src/pcap_file/writer/writer.cpp
    src/pcap_file/parser/parser.cpp
    src/handlers/base_handler.cpp
    src/handlers/ftp_control_handler/ftp_control_handler.cpp
    src/handlers/ftp_data_handler/ftp_data_handler.cpp
    src/handlers/tcp_clean_handler/tcp_clean_handler.hpp
    src/handlers/other_handler/other_handler.cpp
)


target_link_libraries(main PRIVATE ${LIBPCAP_LIBRARY})


