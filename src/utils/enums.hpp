#pragma once


enum EventType {
    FTP_CONTROL = 1,
    FTP_DATA = 2,
    TCP_CLEAN = 3,
    OTHER = 4
};

enum ListenerMode {
    FILE_MODE = 1,
    DIRECTORY_MODE = 2,
    LIVE_MODE = 3
};

enum FtpConnType {
    PASSIVE = 1,
    ACTIVE = 2
};

enum SessionState {
    CLOSED,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSING,
    TIME_WAIT
};