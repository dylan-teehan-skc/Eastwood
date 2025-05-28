#include "endpoints.h"

#include <nlohmann/json.hpp>

#include "src/key_exchange/utils.h"
#include "src/utils/ConversionUtils.h"
#include "src/client_api_interactions/MakeAuthReq.h"
#include "src/sql/queries.h"
#include "src/client_api_interactions/MakeUnauthReq.h"

using json = nlohmann::json;

void post_register_user(
    const std::string &username,
    const unsigned char pk_identity[crypto_sign_PUBLICKEYBYTES],
    const unsigned char registration_nonce[CHA_CHA_NONCE_LEN],
    const unsigned char nonce_signature[crypto_sign_BYTES]
) {
    const json body = {
        {"username", username},
        {"identity_public", bin2hex(pk_identity, crypto_sign_PUBLICKEYBYTES)},
        {"nonce", bin2hex(registration_nonce, CHA_CHA_NONCE_LEN)},
        {"nonce_signature", bin2hex(nonce_signature, crypto_sign_BYTES)}
    };
    std::cout << body << std::endl;

    post_unauth(body, "/registerUser");
};

void post_register_device(
    const unsigned char pk_id[crypto_sign_PUBLICKEYBYTES],
    const unsigned char pk_device[crypto_sign_PUBLICKEYBYTES],
    const unsigned char pk_signature[crypto_sign_BYTES]
) {
    const json body = {
        {"identity_public", bin2hex(pk_id, crypto_sign_PUBLICKEYBYTES)},
        {"device_public", bin2hex(pk_device, crypto_sign_PUBLICKEYBYTES)},
        {"signature", bin2hex(pk_signature, crypto_sign_BYTES)}
    };
    post_unauth(body, "/registerDevice");
};

std::vector<unsigned char> post_request_login(
    std::string username,
    const unsigned char pk_device[crypto_sign_PUBLICKEYBYTES]
) {
    qDebug() << "Requesting login nonce from server";
    const json body = {
        {"username", username},
        {"device_public", bin2hex(pk_device, crypto_sign_PUBLICKEYBYTES)}
    };
    const json response = post_unauth(body, "/requestLogin");
    QString response_text(response.dump().data());
    const std::string nonce_string = response["data"]["nonce"];

    // Allocate vector of correct size
    std::vector<unsigned char> nonce_vec(nonce_string.length() / 2);

    // Convert hex to bin
    if (!hex_to_bin(nonce_string, nonce_vec.data(), nonce_vec.size())) {
        throw std::runtime_error("Failed to decode nonce when logging in");
    }

    return nonce_vec;
}

std::string post_authenticate(
    std::string username,
    const unsigned char pk_device[crypto_sign_PUBLICKEYBYTES],
    unsigned char signature[crypto_sign_BYTES]
) {
    qDebug() << "Authenticating user";
    const json body = {
        {"username", username},
        {"device_public", bin2hex(pk_device, crypto_sign_PUBLICKEYBYTES)},
        {"nonce_signature", bin2hex(signature, crypto_sign_BYTES)}
    };
    const json response = post_unauth(body, "/authenticate");
    return response["data"]["token"];
}

void get_messages(SessionManager manager) {
    auto device_key = get_public_key("device");
    std::string device_key_str = device_key.toStdString();
    //TODO: get vector of messages and parse individually and send on through identity
    json response = get("/getMessages/" + device_key_str);

    DeviceMessage msg;
    msg.header = new MessageHeader();

    std::vector<uint8_t> device_id = hex_string_to_binary(response["device_id"]);
    std::vector<uint8_t> dh_public = hex_string_to_binary(response["dh_public"]);
    std::vector<uint8_t> ciphertext = hex_string_to_binary(response["ciphertext"]);

    std::copy(device_id.begin(), device_id.end(), msg.header->device_id);
    std::copy(dh_public.begin(), dh_public.end(), msg.header->dh_public);
    msg.header->prev_chain_length = response["prev_chain_length"];
    msg.header->message_index = response["message_index"];

    // Allocate and copy ciphertext
    msg.ciphertext = new unsigned char[ciphertext.size()];
    std::copy(ciphertext.begin(), ciphertext.end(), msg.ciphertext);
    msg.length = ciphertext.size();

    // Get the other identity key from the response
    std::vector<uint8_t> other_identity = hex_string_to_binary(response["other_identity"]);
    auto other_pk = new unsigned char[other_identity.size()];
    std::copy(other_identity.begin(), other_identity.end(), other_pk);

    // Route the message to the identity session
    manager.routeToIdentity(msg, other_pk);

    delete[] other_pk;
}

void post_ratchet_message(const DeviceMessage *msg) {
    json body = {
        {"device_id", bin_to_hex(msg->header->device_id, sizeof(msg->header->device_id))},
        {"dh_public", bin_to_hex(msg->header->dh_public, sizeof(msg->header->dh_public))},
        {"prev_chain_length", msg->header->prev_chain_length},
        {"prev_chain_length", msg->header->message_index},
        {"ciphertext", bin_to_hex(msg->ciphertext, sizeof(msg->ciphertext))},
    };
    //todo: post to /sendMessage/deviceId

    post(body, "/sendMessage");
};

void get_keybundles(unsigned char pk_identity[crypto_sign_PUBLICKEYBYTES], SessionManager &manager) {
    char hex_pk_identity[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(hex_pk_identity, sizeof(hex_pk_identity), pk_identity, crypto_sign_PUBLICKEYBYTES);

    json response = get("/keybundle/" + std::string(hex_pk_identity));

    keyBundleRequest request;

    // Copy the identity public key
    request.my_identity_public = new unsigned char[crypto_sign_PUBLICKEYBYTES];
    memcpy(request.my_identity_public, pk_identity, crypto_sign_PUBLICKEYBYTES);

    // Copy their identity public key from response
    std::vector<uint8_t> their_identity = hex_string_to_binary(response["identity_public_key"]);
    request.their_identity_public = new unsigned char[crypto_sign_PUBLICKEYBYTES];
    memcpy(request.their_identity_public, their_identity.data(), crypto_sign_PUBLICKEYBYTES);

    // Process each key bundle
    for (const auto &bundle: response["key_bundles"]) {
        keyBundle kb;

        // Allocate and copy device public key
        std::vector<uint8_t> device_public = hex_string_to_binary(bundle["device_public_key"]);
        kb.device_key_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
        memcpy(kb.device_key_public, device_public.data(), crypto_box_PUBLICKEYBYTES);

        // Allocate and copy signed prekey public key if present
        if (!bundle["presigned_key"].is_null() && !bundle["presigned_key"].empty()) {
            std::vector<uint8_t> signed_prekey = hex_string_to_binary(bundle["presigned_key"]);
            kb.signed_prekey_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
            memcpy(kb.signed_prekey_public, signed_prekey.data(), crypto_box_PUBLICKEYBYTES);
        } else {
            kb.signed_prekey_public = nullptr;
        }

        // Allocate and copy one-time prekey public key if present
        if (!bundle["one_time_key"].is_null() && !bundle["one_time_key"].empty()) {
            std::vector<uint8_t> one_time_prekey = hex_string_to_binary(bundle["one_time_key"]);
            kb.onetime_prekey_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
            memcpy(kb.onetime_prekey_public, one_time_prekey.data(), crypto_box_PUBLICKEYBYTES);
        } else {
            kb.onetime_prekey_public = nullptr;
        }

        request.key_bundles.push_back(kb);
    }

    // Route the keybundle request through the identity session
    manager.import_key_bundles(request);
}


void post_handshake_device(
    const unsigned char *recipient_device_key_public,
    const unsigned char *recipient_signed_prekey_public,
    const unsigned char *recipient_onetime_prekey_public,
    const unsigned char *my_device_key_public,
    const unsigned char *my_ephemeral_key_public
) {
    json body = {
        {"recipient_device_key", bin2hex(recipient_device_key_public, crypto_box_PUBLICKEYBYTES)},
        {"recipient_signed_prekey", bin2hex(recipient_signed_prekey_public, crypto_box_PUBLICKEYBYTES)},
        {"recipient_onetime_prekey", bin2hex(recipient_onetime_prekey_public, crypto_box_PUBLICKEYBYTES)},
        {"my_device_key", bin2hex(my_device_key_public, crypto_box_PUBLICKEYBYTES)},
        {"my_ephemeral_key", bin2hex(my_ephemeral_key_public, crypto_box_PUBLICKEYBYTES)}
    };
    post(body, "/handshake");
}
