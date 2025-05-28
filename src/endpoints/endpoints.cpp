#include "endpoints.h"

#include <nlohmann/json.hpp>

#include "src/key_exchange/utils.h"
#include "src/utils/ConversionUtils.h"
#include "src/client_api_interactions/MakeAuthReq.h"
#include "src/sql/queries.h"
#include "src/client_api_interactions/MakeUnauthReq.h"
#include "src/sessions/IdentityManager.h"
#include "src/utils/utils.h"

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

void get_messages() {
    // TODO: implement or remove
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

void get_keybundles(std::string username) {
    json response = get("/keybundle/" + username);

    // Get my identity public key
    std::string my_identity_public_hex = response["data"]["identity_public_key"];
    unsigned char* my_identity_public = new unsigned char[crypto_sign_PUBLICKEYBYTES];
    if (!hex_to_bin(my_identity_public_hex, my_identity_public, crypto_sign_PUBLICKEYBYTES)) {
        delete[] my_identity_public;
        throw std::runtime_error("Failed to decode my identity public key");
    }

    // Get my device and signed prekey private keys from database
    const auto [pk_device, esk_device, nonce_device] = get_keypair("device");
    const auto [pk_signed, esk_signed, nonce_signed] = get_keypair("signed");
    
    const auto sk_device = decrypt_secret_key(esk_device, nonce_device);
    const auto sk_signed = decrypt_secret_key(esk_signed, nonce_signed);

    std::vector<KeyBundle*> bundles;
    std::string their_identity_public_hex;

    // Process each key bundle
    for (const auto& bundle : response["data"]["key_bundles"]) {
        // Convert hex strings to binary
        std::string their_device_public_hex = bundle["device_public_key"];
        their_identity_public_hex = bundle["identity_public_key"];
        std::string their_onetime_public_hex = bundle["one_time_key"];
        std::string their_signed_public_hex = bundle["signedpre_key"];
        std::string their_signed_signature_hex = bundle["signedpk_signature"];

        // Allocate memory for binary data
        unsigned char* their_device_public = new unsigned char[crypto_sign_PUBLICKEYBYTES];
        unsigned char* their_identity_public = new unsigned char[crypto_sign_PUBLICKEYBYTES];
        unsigned char* their_onetime_public = new unsigned char[crypto_sign_PUBLICKEYBYTES];
        unsigned char* their_signed_public = new unsigned char[crypto_sign_PUBLICKEYBYTES];
        unsigned char* their_signed_signature = new unsigned char[crypto_sign_BYTES];

        // Convert hex to binary
        if (!hex_to_bin(their_device_public_hex, their_device_public, crypto_sign_PUBLICKEYBYTES) ||
            !hex_to_bin(their_identity_public_hex, their_identity_public, crypto_sign_PUBLICKEYBYTES) ||
            !hex_to_bin(their_onetime_public_hex, their_onetime_public, crypto_sign_PUBLICKEYBYTES) ||
            !hex_to_bin(their_signed_public_hex, their_signed_public, crypto_sign_PUBLICKEYBYTES) ||
            !hex_to_bin(their_signed_signature_hex, their_signed_signature, crypto_sign_BYTES)) {
            // Clean up on error
            delete[] their_device_public;
            delete[] their_identity_public;
            delete[] their_onetime_public;
            delete[] their_signed_public;
            delete[] their_signed_signature;
            throw std::runtime_error("Failed to decode key bundle data");
        }

        // Create a new ReceivingKeyBundle
        auto* key_bundle = new ReceivingKeyBundle(
            their_device_public,
            their_signed_public,
            my_identity_public,
            sk_device->data(),  // my_device_private from database
            sk_signed->data(),  // my_signed_private from database
            their_onetime_public
        );

        bundles.push_back(key_bundle);
    }

    // Convert their identity public key to binary
    unsigned char* their_identity_public = new unsigned char[crypto_sign_PUBLICKEYBYTES];
    if (!hex_to_bin(their_identity_public_hex, their_identity_public, crypto_sign_PUBLICKEYBYTES)) {
        delete[] their_identity_public;
        throw std::runtime_error("Failed to decode their identity public key");
    }

    // Update or create identity session
    IdentityManager::getInstance().update_or_create_identity_sessions(bundles, my_identity_public, their_identity_public);
}

void post_handshake_device(
    const unsigned char *identity_session_id,
    const unsigned char *recipient_device_key_public,
    const unsigned char *recipient_signed_prekey_public,
    const unsigned char *recipient_signed_prekey_signature,
    const unsigned char *recipient_onetime_prekey_public,
    const unsigned char *my_device_key_public,
    const unsigned char *my_ephemeral_key_public
) {
    json body = {
        {"identity_session_id", bin2hex(identity_session_id, crypto_box_PUBLICKEYBYTES * 2)},
        {"recipient_device_key", bin2hex(recipient_device_key_public, crypto_box_PUBLICKEYBYTES)},
        {"recipient_signed_prekey", bin2hex(recipient_signed_prekey_public, crypto_box_PUBLICKEYBYTES)},
        {"recipient_signed_prekey_signature", bin2hex(recipient_signed_prekey_signature, crypto_box_PUBLICKEYBYTES)},
        {"recipient_onetime_prekey", bin2hex(recipient_onetime_prekey_public, crypto_box_PUBLICKEYBYTES)},
        {"my_device_key", bin2hex(my_device_key_public, crypto_box_PUBLICKEYBYTES)},
        {"my_ephemeral_key", bin2hex(my_ephemeral_key_public, crypto_box_PUBLICKEYBYTES)}
    };
    post(body, "/handshake");
}

void post_new_keybundles(){
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    
    // Generate new keypair
    crypto_sign_keypair(pk, sk);

    //TODO:: save signed prekey bundle to db
    
    // Convert keys to hex strings
    std::string pk_hex = bin2hex(pk, crypto_sign_PUBLICKEYBYTES);
    std::string sk_hex = bin2hex(sk, crypto_sign_SECRETKEYBYTES);

    auto decrypted_device_key = get_decrypted_sk("device");
    
    // Convert QByteArray to hex string
    std::string device_key_hex = bin_to_hex(decrypted_device_key->data(), decrypted_device_key->size());
    
    // Convert hex string to bytes
    unsigned char device_key[crypto_sign_SECRETKEYBYTES];
    if (!hex_to_bin(device_key_hex, device_key, crypto_sign_SECRETKEYBYTES)) {
        std::cerr << "Failed to convert device key hex to binary" << std::endl;
        throw;
    }
    
    // Sign the public key with device key
    unsigned char signature[crypto_sign_BYTES];
    crypto_sign_detached(signature, nullptr, pk, crypto_sign_PUBLICKEYBYTES, device_key);
    
    // Convert signature to hex string
    std::string signature_hex = bin2hex(signature, crypto_sign_BYTES);
    
    // Create JSON payload
    json body = {
        {"signedpre_key", pk_hex},
        {"signedpk_signature", signature_hex},
        {"one_time_keys", json::array()}
    };

    for (int i = 0; i < 100; i++) {
        unsigned char onetime_pk[crypto_box_PUBLICKEYBYTES];
        unsigned char onetime_sk[crypto_box_SECRETKEYBYTES];
        
        // Generate new keypair
        crypto_box_keypair(onetime_pk, onetime_sk);
        
        // Convert public key to hex
        std::string onetime_pk_hex = bin2hex(onetime_pk, crypto_box_PUBLICKEYBYTES);
        
        // Add to JSON array
        body["onetime_prekeys"].push_back(onetime_pk_hex);
        
        // TODO: Save onetime_sk to database for later use
    }
    
    // Send to server
    post(body, "/updateKeybundle");

}
