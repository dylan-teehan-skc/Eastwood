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
#define BUFFER_SIZE 8192 // 8KB

namespace webwood {

    class HTTPSClient : public BaseClient {
    public:
        HTTPSClient();
        explicit HTTPSClient(const std::string& certPath);
        virtual ~HTTPSClient();

        // Prevent copying
        HTTPSClient(const HTTPSClient&) = delete;
        HTTPSClient& operator=(const HTTPSClient&) = delete;

        // HTTP methods
        std::string get(const std::string& host, const std::string& path, const std::string& headers);
        std::string get(const std::string& host, const std::string& path, std::string& port, const std::string& headers);
        std::string post(const std::string& host, const std::string& path, const std::string& headers, const std::string& body);
        std::string post(const std::string& host, const std::string& path, const std::string& headers, const std::string& body, const std::string& port);

    private:
        std::string certPath;

        struct SSL_CTX_Deleter {
            void operator()(SSL_CTX* ctx) const {
                if (ctx) {
                    SSL_CTX_free(ctx);
                }
            }
        };

        std::unique_ptr<SSL_CTX, SSL_CTX_Deleter> ctx;

        static void init();
        static std::string defaultPort(bool https = true) {
            return https ? "443" : "80";
        }

        std::string formatHeaders(const std::string& headers);

    protected:
        void log(const std::string& msg);
    };

} // namespace webwood

#endif // HTTPSCLIENT_H
