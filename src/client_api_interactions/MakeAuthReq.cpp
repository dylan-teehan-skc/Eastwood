#include <sodium.h>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include "../libraries/HTTPSClient.h"
#include "../algorithms/algorithms.h"
#include "../utils/ConversionUtils.h"
#include "../utils/JsonParser.h"

using json = nlohmann::json;

json post(const json& data, const std::string& endpoint = "/") {

    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char private_key[crypto_box_SECRETKEYBYTES];
    unsigned char session_token[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    // TODO - this should be pulled from db

    // std::string pub_key_hex = db.get_public_key();
    // std::string priv_key_hex = db.get_private_key();
    // std::string sess_key_hex = db.get_session_token();

    std::string pub_key_hex = "AA6AC815B5859DFE390C7036BBAD44CDFD786CFAD51DC5805ECDC42F150CFD2D";
    std::string priv_key_hex = "68184CD166663D8C78803C8F8DF4311FCD8F0B69EAADC7C124F1B492ADE8832D";
    std::string sess_key_hex = "3132333435363738393031323334353637383930313233343536373839303132";
    
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
    unsigned char nonce[NONCE_LEN];
    randombytes_buf(nonce, sizeof nonce);


    char b64_nonce[NONCE_LEN * 2];
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
        std::cerr << "HTTP Error: " << e.what() << std::endl;
        throw;
    } catch (const std::exception& e) {
        std::cerr << "Error parsing response: " << e.what() << std::endl;
        throw;
    }
}

json get(const std::string& endpoint = "/") {

    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char private_key[crypto_box_SECRETKEYBYTES];
    unsigned char session_token[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    // TODO - this should be pulled from db

    // std::string pub_key_hex = db.get_public_key();
    // std::string priv_key_hex = db.get_private_key();
    // std::string sess_key_hex = db.get_session_token();

    std::string pub_key_hex = "AA6AC815B5859DFE390C7036BBAD44CDFD786CFAD51DC5805ECDC42F150CFD2D";
    std::string priv_key_hex = "68184CD166663D8C78803C8F8DF4311FCD8F0B69EAADC7C124F1B492ADE8832D";
    std::string sess_key_hex = "3132333435363738393031323334353637383930313233343536373839303132";
    
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
    unsigned char nonce[NONCE_LEN];
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
        std::cerr << "HTTP Error: " << e.what() << std::endl;
        throw;
    } catch (const std::exception& e) {
        std::cerr << "Error parsing response: " << e.what() << std::endl;
        throw;
    }
}