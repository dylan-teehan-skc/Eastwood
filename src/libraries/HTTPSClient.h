//
// Created by niall on 20/05/25.
//

#ifndef HTTPSCLIENT_H
#define HTTPSCLIENT_H
#pragma once
#include "BaseClient.h"
#include <string>
#include <memory>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdexcept>

namespace webwood {
    class HTTPSClient : public BaseClient {
    public:
        HTTPSClient();
        explicit HTTPSClient(const std::string& certPath);
        virtual ~HTTPSClient();
        HTTPSClient& operator=(const HTTPSClient&) = delete;

        std::string get(const std::string& host, const std::string& path , const std::string &headers);
        std::string get(const std::string& host, const std::string& path, std::string& port, const std::string &headers);
        std::string post(const std::string& host, const std::string& path, const std::string &headers, const std::string& body);
        std::string post(const std::string& host, const std::string& path, const std::string &headers, const std::string &body, const std::string& port);
    private:
        std::string certPath;
        struct SSL_CTX_Deleter {
            void operator()(SSL_CTX* ctx) const {
                if (ctx) {
                    SSL_CTX_free(ctx);
                    ctx = nullptr;
                }
            }
        };
        std::unique_ptr<SSL_CTX, SSL_CTX_Deleter> ctx;

        static void init();
        static std::string defaultPort(bool https = true) {
            return https ? "443" : "80";
        }

    protected:
        void log(const std::string& msg);
    };
}

#endif //HTTPSCLIENT_H