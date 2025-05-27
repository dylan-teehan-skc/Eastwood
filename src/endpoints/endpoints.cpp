#include "endpoints.h"
#include <nlohmann/json.hpp>

#include "src/key_exchange/utils.h"
#include "src/utils/ConversionUtils.h"
#include "src/client_api_interactions/MakeAuthReq.h"

using json = nlohmann::json;

void post_register_user(
    const std::string &username,
    unsigned char pk_identity[crypto_sign_PUBLICKEYBYTES],
    unsigned char registration_nonce[NONCE_LEN],
    unsigned char nonce_signature[crypto_sign_BYTES]
) {
    json body = {
        {"username", username},
        {"identity_public", bin2hex(pk_identity, crypto_sign_PUBLICKEYBYTES)},
        {"nonce", bin2hex(registration_nonce, NONCE_LEN)},
        {"nonce_signature", bin2hex(nonce_signature, crypto_sign_BYTES)}
    };

    post(body, "/registerUser");
};

void post_register_device(
    unsigned char pk_id[crypto_sign_PUBLICKEYBYTES],
    unsigned char pk_device[crypto_sign_PUBLICKEYBYTES],
    unsigned char pk_signature[crypto_sign_BYTES]
) {
    json body = {
        {"identity_public", bin2hex(pk_id, crypto_sign_PUBLICKEYBYTES)},
        {"device_public", bin2hex(pk_device, crypto_sign_PUBLICKEYBYTES)},
        {"signature", bin2hex(pk_signature, crypto_sign_BYTES)}
    };
    post(body, "/registerDevice");
};

Message* get_messages() {
    // TODO: GET /getMessages/device

    //TODO: get vector of messages and parse individually and send on through identity
    json response = json::parse(""); // Replace with actual API response

    Message* msg = new Message();
    msg->header = new MessageHeader();

    std::vector<uint8_t> device_id = hex_string_to_binary(response["device_id"]);
    std::vector<uint8_t> dh_public = hex_string_to_binary(response["dh_public"]);
    std::vector<uint8_t> ciphertext = hex_string_to_binary(response["ciphertext"]);

    std::copy(device_id.begin(), device_id.end(), msg->header->device_id);
    std::copy(dh_public.begin(), dh_public.end(), msg->header->dh_public);
    msg->header->prev_chain_length = response["prev_chain_length"];
    msg->header->message_index = response["message_index"];
    std::copy(ciphertext.begin(), ciphertext.end(), msg->message);

    return msg;

    // todo: route through identity session?
};

void post_ratchet_message(const DeviceMessage* msg) {
    json body = {
        {"device_id", bin_to_hex(msg->header->device_id, sizeof(msg->header->device_id))},
        {"dh_public", bin_to_hex(msg->header->dh_public, sizeof(msg->header->dh_public))},
        {"prev_chain_length", msg->header->prev_chain_length},
        {"prev_chain_length", msg->header->message_index},
        {"ciphertext", bin_to_hex(msg->ciphertext, sizeof(msg->ciphertext))},
    };
    //todo: post to /sendMessage/deviceId
};

keyBundleRequest get_keybundles(unsigned char pk_identity[32]) {
    std::string hex_pk_identity = bin2hex(pk_identity, 32);
    std::string response = get("/keybundle/"+hex_pk_identity);

    //TODO:: parse response
};
