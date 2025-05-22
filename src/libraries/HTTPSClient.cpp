//
// Created by niall on 20/05/25.
//

#include "./HTTPSClient.h"

using namespace webwood;
void HTTPSClient::init() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}
HTTPSClient::HTTPSClient() {
    init();
    ctx.reset(SSL_CTX_new(TLS_client_method()));  // Create and assign SSL_CTX
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Failed to create SSL context");
    }

    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_default_verify_paths(ctx.get());
}

HTTPSClient::HTTPSClient(const std::string& certPath) : certPath(certPath) {
    init();
    ctx.reset(SSL_CTX_new(TLS_client_method()));  // Create and assign SSL_CTX
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Failed to create SSL context");
    }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);

    if (!SSL_CTX_load_verify_locations(ctx.get(), certPath.c_str(), nullptr)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx.get());
        throw std::runtime_error("Failed to load certificate from path: " + certPath);
    }
}

std::string HTTPSClient::get(const std::string& host, const std::string& path, std::string& port) {
    int sock_fd = create_socket(host.c_str(), port.c_str());
    if (sock_fd < 0) {
        SSL_CTX_Deleter(ctx);
        return "Socket connection closed / lost";
    }
    SSL* ssl = SSL_new(ctx.get());
    SSL_set_fd(ssl, sock_fd);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    SSL_set1_host(ssl, host.c_str());

    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        SSL_CTX_Deleter(ctx);
        close(sock_fd);
        return "TLS handshake failed";
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        SSL_free(ssl);
        SSL_CTX_Deleter(ctx);
        close(sock_fd);
        return "Certificate verification failed";
    }

    std::string req =
        "GET " + path + " HTTP/1.1\r\n" +
        "Host: " + host + "\r\n" +
        "Connection: close\r\n\r\n";
    SSL_write(ssl, req.c_str(), req.length());

    char buf[4096];
    std::string response;
    int bytes;

    while ((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        response.append(buf, bytes);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_Deleter(ctx);
    close(sock_fd);

    return response;
}


std::string HTTPSClient::get(const std::string &host, const std::string &path) {
    int sock_fd = create_socket(host.c_str(), defaultPort(true).c_str());
    if (sock_fd < 0) {
        SSL_CTX_Deleter(ctx);
        return "Socket connection closed / lost";
    }
    SSL* ssl = SSL_new(ctx.get());
    SSL_set_fd(ssl, sock_fd);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    SSL_set1_host(ssl, host.c_str());

    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        SSL_CTX_Deleter(ctx);
        close(sock_fd);
        return "TLS handshake failed";
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        SSL_free(ssl);
        SSL_CTX_Deleter(ctx);
        close(sock_fd);
        return "Certificate verification failed";
    }

    std::string req =
        "GET " + path + " HTTP/1.1\r\n" +
        "Host: " + host + "\r\n" +
        "Connection: close\r\n\r\n";
    SSL_write(ssl, req.c_str(), req.length());

    char buf[4096];
    std::string response;
    int bytes;

    while ((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        response.append(buf, bytes);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_Deleter(ctx);
    close(sock_fd);

    return response;
}

std::string HTTPSClient::post(const std::string& host, const std::string& path, const std::string& body) {
    int sock_fd = create_socket(host.c_str(), defaultPort(true).c_str());
    if (sock_fd < 0) {
        SSL_CTX_Deleter(ctx);
        return "Socket connection failed";
    }

    SSL* ssl = SSL_new(ctx.get());
    SSL_set_fd(ssl, sock_fd);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    SSL_set1_host(ssl, host.c_str());

    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        SSL_CTX_Deleter(ctx);
        close(sock_fd);
        return "TLS handshake failed";
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        SSL_free(ssl);
        SSL_CTX_Deleter(ctx);
        close(sock_fd);
        return "Certificate verification failed";
    }

    std::string request =
        "POST " + path + " HTTP/1.1\r\n" +
        "Host: " + host + "\r\n" +
        "Content-Type: application/json\r\n" +
        "Content-Length: " + std::to_string(body.size()) + "\r\n" +
        "Connection: close\r\n\r\n" +
        body;

    SSL_write(ssl, request.c_str(), request.length());

    char buf[4096];
    std::string response;
    int bytes;
    while ((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        response.append(buf, bytes);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_Deleter(ctx);
    close(sock_fd);

    return response;
}

std::string HTTPSClient::post(const std::string& host, const std::string& path, const std::string& body, const std::string& port) {
    int sock_fd = create_socket(host.c_str(), port.c_str());
    if (sock_fd < 0) {
        SSL_CTX_Deleter(ctx);
        return "Socket connection failed";
    }

    SSL* ssl = SSL_new(ctx.get());
    SSL_set_fd(ssl, sock_fd);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    SSL_set1_host(ssl, host.c_str());

    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        SSL_CTX_Deleter(ctx);
        close(sock_fd);
        return "TLS handshake failed";
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        SSL_free(ssl);
        SSL_CTX_Deleter(ctx);
        close(sock_fd);
        return "Certificate verification failed";
    }

    std::string request =
        "POST " + path + " HTTP/1.1\r\n" +
        "Host: " + host + "\r\n" +
        "Content-Type: application/json\r\n" +
        "Content-Length: " + std::to_string(body.size()) + "\r\n" +
        "Connection: close\r\n\r\n" +
        body;

    SSL_write(ssl, request.c_str(), request.length());

    char buf[4096];
    std::string response;
    int bytes;
    while ((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        response.append(buf, bytes);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_Deleter(ctx);
    close(sock_fd);

    return response;
}


HTTPSClient::~HTTPSClient() {
    SSL_CTX_Deleter(ctx);
    EVP_cleanup(); // Clean up OpenSSL
}