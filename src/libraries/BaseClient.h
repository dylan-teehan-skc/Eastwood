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
#include <unordered_map>
#include <chrono>
#include <mutex>
class BaseClient {
protected:
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> lastRequestTime;
    std::chrono::milliseconds rateLimitDelay{500};
    std::mutex rateLimitMutex;
    void enforceRateLimit(const std::string &host);
public:
    virtual ~BaseClient() = default;
    static int create_socket(const char* hostname, const char* port);
};

#endif //BASECLIENT_H