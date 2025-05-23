#include "endpoints.h"
#include <nlohmann/json.hpp>

#include "src/key_exchange/utils.h"

using json = nlohmann::json;

void post_register_user(
    const std::string &username,
    unsigned char pk_identity[crypto_sign_PUBLICKEYBYTES],
    unsigned char registration_nonce[NONCE_LEN],
    unsigned char nonce_signature[crypto_sign_BYTES]
) {
    json body = {
        {"username", username},
        {"identity_public", bin2base64(pk_identity, crypto_sign_PUBLICKEYBYTES)},
        {"nonce", bin2base64(registration_nonce, NONCE_LEN)},
        {"nonce_signature", bin2base64(nonce_signature, crypto_sign_BYTES)}
    };
    // TODO:  post("/registerUser", body.dump());
};

void post_register_device(
    unsigned char pk_id[crypto_sign_PUBLICKEYBYTES],
    unsigned char pk_device[crypto_sign_PUBLICKEYBYTES],
    unsigned char pk_signature[crypto_sign_BYTES]
) {
    json body = {
        {"identity_public", bin2base64(pk_id, crypto_sign_PUBLICKEYBYTES)},
        {"device_public", bin2base64(pk_device, crypto_sign_PUBLICKEYBYTES)},
        {"signature", bin2base64(pk_signature, crypto_sign_BYTES)}
    };
    // TODO:  post("/registerDevice", body.dump());
};
