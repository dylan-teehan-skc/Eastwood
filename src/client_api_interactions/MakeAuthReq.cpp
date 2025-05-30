#include <sodium.h>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include "../libraries/HTTPSClient.h"
#include "../utils/ConversionUtils.h"
#include "../utils/JsonParser.h"
#include "../sql/queries.h"
#include "src/keys/session_token_manager.h"
#include "src/key_exchange/utils.h"
#include "src/utils/utils.h"

using json = nlohmann::json;

std::string pk_device_hex() {
    auto pk_device = get_public_key("device");
    return bin2hex(reinterpret_cast<const unsigned char *>(pk_device.data()), pk_device.size());
}

/**
 *
 * @param message The json body or nonce to be signed
 * @return The hex-encoded signature
 */
std::string sign_message(const std::string &message) {
    const auto sk_device = get_decrypted_sk("device");

    unsigned char signature[crypto_sign_BYTES];
    crypto_sign_detached(
        signature, nullptr,
        reinterpret_cast<const unsigned char *>(message.data()),
        message.length(),
        sk_device->data()
    );
    return bin2hex(signature, crypto_sign_BYTES);
}

std::string sign_nonce(const unsigned char nonce[CHA_CHA_NONCE_LEN]) {
    const auto sk_device = get_decrypted_sk("device");

    unsigned char signature[crypto_sign_BYTES];
    crypto_sign_detached(
        signature, nullptr,
        nonce,
        CHA_CHA_NONCE_LEN,
        sk_device->data()
    );
    return bin2hex(signature, crypto_sign_BYTES);
}

std::string generate_get_headers(const unsigned char nonce[CHA_CHA_NONCE_LEN]) {
    std::map<std::string, std::string> headers = {
        {"device_public", pk_device_hex()},
        {"signature", sign_nonce(nonce)},
        {"nonce", bin2hex(nonce, CHA_CHA_NONCE_LEN)},
        {"session_token", SessionTokenManager::instance().getToken()}
    };

    // Convert the map of headers into a single string
    std::string header_string;
    for (const auto &[key, value]: headers) {
        header_string.append(key).append(": ").append(value).append("\r\n");
    }
    return header_string;
}


json generate_post_headers(const std::string &request_body) {
    std::map<std::string, std::string> headers = {
        {"device_public", pk_device_hex()},
        {"signature", sign_message(request_body)},
        {"session_token", SessionTokenManager::instance().getToken()}
    };

    // Convert the map of headers into a single string
    std::string header_string;
    for (const auto &[key, value]: headers) {
        header_string.append(key).append(": ").append(value).append("\n");
    }
    return header_string;
}

json handle_response(const std::string &response) {
    try {
        qDebug() << response;
        return webwood::parse_json_response(response);
    } catch (const webwood::HttpError &e) {
        throw webwood::HttpError(webwood::extract_response_body(response), e.get_status_code());
    } catch (const std::exception &) {
        throw webwood::HttpError(webwood::extract_response_body(response), 0);
    }
}


json get(const std::string &endpoint = "/") {
    const std::string API_HOST = load_env_variable("API_HOST");
    if (API_HOST.empty()) {
        std::cerr << "API_HOST not found in .env file" << std::endl;
        throw;
    }

    unsigned char nonce[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce, CHA_CHA_NONCE_LEN);

    const std::string headers = generate_get_headers(nonce);

    webwood::HTTPSClient client;
    const std::string response = client.get(API_HOST, endpoint, headers);
    return handle_response(response);
}

json post(const std::string &endpoint, const json &data) {
    const std::string API_HOST = load_env_variable("API_HOST");
    if (API_HOST.empty()) {
        std::cerr << "API_HOST not found in .env file" << std::endl;
        throw;
    }

    unsigned char nonce[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce, CHA_CHA_NONCE_LEN);

    json request_json = data;
    request_json["nonce"] = bin2hex(nonce, CHA_CHA_NONCE_LEN);
    const std::string request_body = request_json.dump();
    const std::string headers = generate_post_headers(request_body);

    webwood::HTTPSClient client;
    const std::string response = client.post(API_HOST, endpoint, headers, request_body);
    return handle_response(response);
}