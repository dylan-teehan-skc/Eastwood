#ifndef ENDPOINTS_H
#define ENDPOINTS_H
#include <string>
#include <sodium.h>
#include <array>
#include "src/algorithms/constants.h"
#include "src/keys/secure_memory_buffer.h"
#include "src/key_exchange/MessageStructs.h"
#include "src/sessions/KeyBundle.h"
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

bool post_check_user_exists(const std::string& username, const unsigned char* pk_device);

std::vector<std::string> get_devices();

void post_register_user(
    const std::string &username,
    const unsigned char pk_identity[crypto_sign_PUBLICKEYBYTES],
    const unsigned char registration_nonce[CHA_CHA_NONCE_LEN],
    const unsigned char nonce_signature[crypto_sign_BYTES]
);

void post_register_device(
    const unsigned char pk_id[crypto_sign_PUBLICKEYBYTES],
    const unsigned char pk_device[crypto_sign_PUBLICKEYBYTES],
    const unsigned char pk_signature[crypto_sign_BYTES],
    const std::string &device_name
);

std::vector<unsigned char> post_request_login(
    std::string username,
    const unsigned char pk_device[crypto_sign_PUBLICKEYBYTES]
);

std::string post_authenticate(
    std::string username,
    const unsigned char pk_device[crypto_sign_PUBLICKEYBYTES],
    unsigned char signature[crypto_sign_BYTES]
);

void post_ratchet_message(
    std::vector<std::tuple<std::array<unsigned char,32>, DeviceMessage*>>,
    std::string username
);

void post_handshake_device(
    const unsigned char *recipient_device_key_public,
    const unsigned char *recipient_signed_prekey_public,
    const unsigned char *recipient_signed_prekey_signature,
    const unsigned char *recipient_onetime_prekey_public,
    const unsigned char *my_ephemeral_key_public
);

// [ <username, keybundle (includes device id)> ]
std::vector<std::tuple<std::string, KeyBundle*>> get_handshake_backlog();

// [ <username, message (includes device id) > ]
std::vector<std::tuple<std::string, DeviceMessage>> get_messages();

std::vector<KeyBundle*> get_keybundles(const std::string &username, std::vector<std::array<unsigned char,32>> existing_device_ids);

// Overloaded versions - with signed prekey (original signature)
void post_new_keybundles(
    std::tuple<QByteArray, std::unique_ptr<SecureMemoryBuffer> > device_keypair,
    std::tuple<unsigned char *, std::unique_ptr<SecureMemoryBuffer> > *signed_prekeypair,
    const std::vector<std::tuple<unsigned char *, std::unique_ptr<SecureMemoryBuffer>, unsigned char *> > &otks
);

std::string post_upload_file(
    const std::vector<unsigned char>& encrypted_file_data,
    const std::vector<unsigned char>& encrypted_metadata
);

bool post_check_user_exists(
    const std::string& username
);

bool get_user_exists(
    const std::string& username
);

std::vector<std::string> get_devices();

std::vector<unsigned char> get_encrypted_file(std::string uuid);

std::map<std::string, std::vector<unsigned char>> get_encrypted_file_metadata(std::vector<std::string> uuids);

void post_delete_file(const std::string &uuid);

#endif //ENDPOINTS_H
