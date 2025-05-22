#include <sodium.h>
#include <nlohmann/json.hpp>
#include <iostream>

bool make_auth_request(std::string api_url, std::string public_key, std::string private_key, std::string session_key) {
    
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char session_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    unsigned char nonce[32];
    randombytes_buf(nonce, sizeof nonce);

    unsigned char signature[crypto_sign_BYTES];
    crypto_sign_detached(signature, nullptr, nonce, sizeof(nonce), private_key);

    json payload = {
            {"public_key", to_hex(public_key, sizeof(public_key))},
            {"signature", to_hex(signature, sizeof(signature))},
            {"session_key", to_hex(session_key, sizeof(session_key))}
        };

    std::string request_body = payload.dump();

    std::map<std::string, std::string> headers = {
            {"Content-Type", "application/json"}
    };

    std::string response = client.post(.....)
}


