//
// Created by niall on 20/05/25.
//

#ifndef BASECLIENT_H
#define BASECLIENT_H
#pragma once
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

class BaseClient {
public:
    virtual std::string get(const std::string& host, const std::string& path) = 0;
    virtual ~BaseClient() = default;
    static int create_socket(const char* hostname, const char* port);
};

#endif //BASECLIENT_H