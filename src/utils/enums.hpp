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
    LIVE_MODE = 3,
    UNDEFINE = 4
};

enum FtpConnType {
    PASSIVE = 1,
    ACTIVE = 2
};

enum SessionState {
    CLOSED,
    SYN_SENT_1,
    SYN_SENT_2,
    ESTABLISHED,
    FIN_SENT_1,
    FIN_ACK_1,
    FIN_SENT_2,
    TWO_FIN,
    CLOSING,
};