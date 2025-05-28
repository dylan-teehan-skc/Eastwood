#include <sodium.h>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include "../libraries/HTTPSClient.h"
#include "../algorithms/algorithms.h"
#include "../utils/ConversionUtils.h"
#include "../utils/JsonParser.h"
#include "../sql/queries.h"

using json = nlohmann::json;
json post(const json& data, const std::string& endpoint = "/") {
    return 0;
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char private_key[crypto_box_SECRETKEYBYTES];
    unsigned char session_token[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    // Get keys from database
    auto public_key_encrypted = get_public_key("auth");
    auto decrypted_private_key = get_decrypted_sk("auth");
    auto decrypted_session_key = get_decrypted_key("session");

    // Convert QByteArray to hex strings
    std::string pub_key_hex = bin_to_hex(reinterpret_cast<const unsigned char*>(public_key_encrypted.data()), public_key_encrypted.size());
    std::string priv_key_hex = bin_to_hex(decrypted_private_key->data(), decrypted_private_key->size());
    std::string sess_key_hex = bin_to_hex(decrypted_session_key->data(), decrypted_session_key->size());
    
    // Convert hex strings to bytes using the utility function
    if (!hex_to_bin(pub_key_hex, public_key, crypto_box_PUBLICKEYBYTES)) {
        std::cerr << "Failed to convert public key hex to binary" << std::endl;
        throw;
    }
    
    if (!hex_to_bin(priv_key_hex, private_key, crypto_box_SECRETKEYBYTES)) {
        std::cerr << "Failed to convert private key hex to binary" << std::endl;
        throw;
    }
    
    if (!hex_to_bin(sess_key_hex, session_token, crypto_aead_xchacha20poly1305_ietf_KEYBYTES)) {
        std::cerr << "Failed to convert session key hex to binary" << std::endl;
        throw;
    }
    // finish

    std::string API_HOST = load_env_variable("API_HOST");
    if (API_HOST.empty()) {
        std::cerr << "API_HOST not found in .env file" << std::endl;
        throw;
    }

    // Generate nonce
    unsigned char nonce[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce, sizeof nonce);


    char b64_nonce[CHA_CHA_NONCE_LEN * 2];
    sodium_bin2base64(b64_nonce, sizeof(b64_nonce),
                    nonce, sizeof(nonce),
                    sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    // Parse and modify JSON
    json request_json = data;
    request_json.push_back({"nonce", std::string(b64_nonce)});
    // convert to string for signing
    std::string request_body = request_json.dump();

    // Sign the request body and nonce with the private key
    unsigned char signature[crypto_sign_BYTES];
    crypto_sign_detached(signature, nullptr, 
                        reinterpret_cast<const unsigned char*>(request_body.c_str()),
                        request_body.length(), 
                        private_key);

    // convert headers to hex
    char hex_public_key[crypto_sign_PUBLICKEYBYTES * 2];
    char hex_signature[crypto_sign_BYTES * 2];
    char hex_session_token[crypto_aead_xchacha20poly1305_ietf_KEYBYTES * 2];

    // TODO - This SIGABRTS?
    sodium_bin2hex(hex_public_key, sizeof(hex_public_key),
                    public_key, crypto_sign_PUBLICKEYBYTES);

    sodium_bin2hex(hex_signature, sizeof(hex_signature),
                    signature, crypto_sign_BYTES);

    sodium_bin2hex(hex_session_token, sizeof(hex_session_token),
                    session_token, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);


    std::map<std::string, std::string> headers = {
        {"Content-Type", "application/json"},
        {"public_key", hex_public_key},
        {"signature", hex_signature},
        {"session_token", hex_session_token}
    };

    // Convert the map of headers into a single string
    std::string header_string;
    for (const auto& [key, value] : headers) {
        header_string.append(key).append(": ").append(value).append("\n");
    }

    webwood::HTTPSClient httpsclient;
    std::string response = httpsclient.post(API_HOST, endpoint, header_string, request_body);
    
    try {
        return webwood::parse_json_response(response);
    } catch (const webwood::HttpError& e) {
        throw webwood::HttpError(webwood::extract_response_body(response), e.get_status_code());
    } catch (const std::exception& e) {
        throw webwood::HttpError(webwood::extract_response_body(response), 0);
    }
}

json get(const std::string& endpoint = "/") {

    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char private_key[crypto_box_SECRETKEYBYTES];
    unsigned char session_token[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    // Get keys from database
    auto public_key_encrypted = get_public_key("auth");
    auto decrypted_private_key = get_decrypted_sk("auth");
    auto decrypted_session_key = get_decrypted_key("session");

    std::string pub_key_hex = bin_to_hex(reinterpret_cast<const unsigned char*>(public_key_encrypted.data()), public_key_encrypted.size());
    std::string priv_key_hex = bin_to_hex(decrypted_private_key->data(), decrypted_private_key->size());
    std::string sess_key_hex = bin_to_hex(decrypted_session_key->data(), decrypted_session_key->size());
    
    // Convert hex strings to bytes
    if (!hex_to_bin(pub_key_hex, public_key, crypto_box_PUBLICKEYBYTES)) {
        std::cerr << "Failed to convert public key hex to binary" << std::endl;
        throw;
    }
    
    if (!hex_to_bin(priv_key_hex, private_key, crypto_box_SECRETKEYBYTES)) {
        std::cerr << "Failed to convert private key hex to binary" << std::endl;
        throw;
    }
    
    if (!hex_to_bin(sess_key_hex, session_token, crypto_aead_xchacha20poly1305_ietf_KEYBYTES)) {
        std::cerr << "Failed to convert session key hex to binary" << std::endl;
        throw;
    }

    // finish

    std::string API_HOST = load_env_variable("API_HOST");
    if (API_HOST.empty()) {
        std::cerr << "API_HOST not found in .env file" << std::endl;
        throw;
    }

    // Generate nonce
    unsigned char nonce[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce, sizeof nonce);

    // Create nonce signed with private key
    unsigned char signature[crypto_sign_BYTES];
    crypto_sign_detached(signature, nullptr, nonce, sizeof(nonce), private_key);

    // convert headers to base64
    char b64_public_key[crypto_sign_PUBLICKEYBYTES * 2];
    char b64_signature[crypto_sign_BYTES * 2];
    char b64_session_token[crypto_aead_xchacha20poly1305_ietf_KEYBYTES * 2];

    sodium_bin2base64(b64_public_key, sizeof(b64_public_key),
                    public_key, crypto_sign_PUBLICKEYBYTES,
                    sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    sodium_bin2base64(b64_signature, sizeof(b64_signature),
                    signature, crypto_sign_BYTES,
                    sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    sodium_bin2base64(b64_session_token, sizeof(b64_session_token),
                    session_token, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                    sodium_base64_VARIANT_URLSAFE_NO_PADDING);


    std::map<std::string, std::string> headers = {
        {"public_key", b64_public_key},
        {"signature", b64_signature},
        {"session_token", b64_session_token}
    };

    // Convert the map of headers into a single string
    std::string header_string;
    for (const auto& [key, value] : headers) {
        header_string.append(key).append(": ").append(value).append("\n");
    }

    webwood::HTTPSClient httpsclient;
    std::string response = httpsclient.get(API_HOST, endpoint, header_string);
    
    try {
        return webwood::parse_json_response(response);
    } catch (const webwood::HttpError& e) {
        throw webwood::HttpError(webwood::extract_response_body(response), e.get_status_code());
    } catch (const std::exception& e) {
        throw webwood::HttpError(webwood::extract_response_body(response), 0);
    }
}