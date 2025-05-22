//
// Created by niall on 21/05/25.
//
#include "./BaseClient.h"

int BaseClient::create_socket(const char* hostname, const char* port) {
    addrinfo *res, hints={0}, *p;
    int sock_fd = -1;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP; // implemented -> no testing done yet
    if (getaddrinfo(hostname, port, &hints, &res) != 0) {
        perror("getaddrinfo failed");
        return -1;
    }

    for (p=res; p != NULL; p = p->ai_next) {
        sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock_fd < 0) continue;
        if (connect(sock_fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(sock_fd);
        sock_fd = -1;
    }
    freeaddrinfo(res);
    return sock_fd;

}