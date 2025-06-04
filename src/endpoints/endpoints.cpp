#include "endpoints.h"

#include <nlohmann/json.hpp>

#include "src/key_exchange/utils.h"
#include "src/client_api_interactions/MakeAuthReq.h"
#include "src/sql/queries.h"
#include "src/client_api_interactions/MakeUnauthReq.h"
#include "src/keys/session_token_manager.h"
#include "src/utils/utils.h"


using json = nlohmann::json;

bool post_check_user_exists(const std::string &username, const unsigned char *pk_device) {
    const json body = {
        {"username", username},
        {"device_public_key", bin2hex(pk_device, 32)}
    };

    json response = post_unauth("/isDeviceRegistered", body);
    std::cout << "Response from server: " << response.dump(4) << std::endl;

    if (!response.contains("data") || !response["data"].is_boolean()) {
        throw std::runtime_error("Invalid or missing 'data' field in response");
    }
    return response["data"].get<bool>();
}

bool get_user_exists(const std::string &username) {
    json response = get_unauth("/isUserRegistered/" + username);
    std::cout << "Response from server: " << response.dump(4) << std::endl;
    return response["data"].get<bool>();
}

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

    post_unauth("/registerUser", body);
};

void post_register_device(
    const unsigned char pk_id[crypto_sign_PUBLICKEYBYTES],
    const unsigned char pk_device[crypto_sign_PUBLICKEYBYTES],
    const unsigned char pk_signature[crypto_sign_BYTES],
    const std::string &device_name
) {
    const json body = {
        {"identity_public", bin2hex(pk_id, crypto_sign_PUBLICKEYBYTES)},
        {"device_public", bin2hex(pk_device, crypto_sign_PUBLICKEYBYTES)},
        {"signature", bin2hex(pk_signature, crypto_sign_BYTES)},
        {"device_name", device_name}
    };
    post_unauth("/registerDevice", body);
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
    const json response = post_unauth("/requestLogin", body);
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
    const json response = post_unauth("/authenticate", body);
    return response["data"]["token"];
}

std::vector<std::tuple<std::string, DeviceMessage> > get_messages() {
    json response;
    try {
        response = get("/incomingMessages");
    } catch (const std::exception &e) {
        return std::vector<std::tuple<std::string, DeviceMessage> >();
    }

    std::cout << "Raw response: " << response.dump() << std::endl;
    std::cout << "Response keys: ";
    for (auto &[key, value]: response.items()) {
        std::cout << key << " ";
    }
    std::cout << std::endl;

    std::vector<std::tuple<std::string, DeviceMessage> > messages;

    // Check if data array exists
    if (!response.contains("data") || !response["data"].is_array()) {
        std::cout << "No messages in response" << std::endl;
        return messages;
    }

    for (const auto &message: response["data"]) {
        const auto username = message["username"].get<std::string>();
        const auto dev_key_str = message["initiator_device_public_key"].get<std::string>();
        const auto dh_pub_str = message["dh_public"].get<std::string>();
        const auto ciphertext_str = message["ciphertext"].get<std::string>();

        int prev_chain_length = message["prev_chain_length"].get<int>();
        int message_index = message["message_index"].get<int>();

        // Extract file_id if present
        std::string file_id;
        if (message.contains("file_id") && !message["file_id"].is_null()) {
            file_id = message["file_id"].get<std::string>();
        }

        // Validate hex string lengths before allocation
        if (dev_key_str.length() != 64 || dh_pub_str.length() != 64) {
            // 32 bytes = 64 hex chars
            std::cerr << "Invalid key hex string lengths" << std::endl;
            continue;
        }

        const auto ciphertext = hex2bin(ciphertext_str);
        const auto initator_dev_key = hex2bin(dev_key_str);
        const auto new_dh_public = hex2bin(dh_pub_str);

        auto msg = DeviceMessage();
        auto header = MessageHeader();

        // Safe copy with correct size (both arrays are 32 bytes)
        memcpy(header.dh_public.data(), new_dh_public.data(), 32);
        header.message_index = message_index;
        header.prev_chain_length = prev_chain_length;
        memcpy(header.device_id.data(), initator_dev_key.data(), 32);

        // Set file_uuid if available
        if (!file_id.empty()) {
            strncpy(header.file_uuid, file_id.c_str(), sizeof(header.file_uuid) - 1);
            header.file_uuid[sizeof(header.file_uuid) - 1] = '\0';
        }

        msg.header = header;
        msg.ciphertext = ciphertext;

        messages.emplace_back(username, msg);
    }
    return messages;
}

void post_ratchet_message(std::vector<std::tuple<std::array<unsigned char, 32>, DeviceMessage *> > messages,
                          std::string username) {
    json data = json::object();
    data["messages"] = json::array();

    for (auto [recipient_dev_pub, msg]: messages) {
        const auto dev_pub = new unsigned char[crypto_box_PUBLICKEYBYTES];
        QByteArray dev_pub_byte = get_public_key("device");
        memcpy(dev_pub, dev_pub_byte.constData(), crypto_box_PUBLICKEYBYTES);

        json body = json::object();
        body["file_id"] = std::string(msg->header.file_uuid);
        body["username"] = SessionTokenManager::instance().getUsername();
        body["initiator_device_public_key"] = bin2hex(dev_pub, 32);
        body["recipient_device_public_key"] = bin2hex(recipient_dev_pub.data(), 32);
        body["dh_public"] = bin2hex(msg->header.dh_public.data(), 32);
        body["prev_chain_length"] = msg->header.prev_chain_length;
        body["message_index"] = msg->header.message_index;
        body["ciphertext"] = bin2hex(msg->ciphertext.data(), msg->ciphertext.size());
        body["ciphertext_length"] = msg->ciphertext.size();

        data["messages"].push_back(body);
        delete[] dev_pub;
    }

    post("/sendMessage", data);
}

std::vector<KeyBundle *> get_keybundles(const std::string &username,
                                        std::vector<std::array<unsigned char, 32> > existing_device_ids) {
    json array_of_device_ids = json::array();

    for (auto device_id: existing_device_ids) {
        array_of_device_ids.push_back(bin2hex(device_id.data(), device_id.size()));
    }

    json body = {
        {"existing_device_ids", array_of_device_ids}
    };

    json response;
    try {
        response = post("/keybundle/" + username, body);
    } catch (const std::exception &e) {
        return std::vector<KeyBundle *>();
    }

    // Get my identity public key
    std::string my_identity_public_hex = response["data"]["identity_public_key"];
    std::array<unsigned char, 32> my_identity_public{};
    if (!hex_to_bin(my_identity_public_hex, my_identity_public.data(), crypto_sign_PUBLICKEYBYTES)) {
        throw std::runtime_error("Failed to decode my identity public key");
    }

    // Get my device and signed prekey private keys from database
    const auto [pk_device, sk_device] = get_decrypted_keypair("device");
    const auto [pk_signed, sk_signed] = get_decrypted_keypair("signed");

    std::vector<KeyBundle *> bundles;
    std::string their_identity_public_hex;

    // Process each key bundle
    for (const auto &bundle: response["data"]["key_bundles"]) {
        std::string their_device_public_hex = bundle["device_public_key"];
        their_identity_public_hex = bundle["identity_public_key"];
        std::string their_signed_public_hex = bundle["signedpre_key"];
        std::string their_signed_signature_hex = bundle["signedpk_signature"];

        // Create arrays for binary data
        std::array<unsigned char, 32> their_device_public{};
        std::array<unsigned char, 32> their_identity_public{};
        std::array<unsigned char, 32> their_signed_public{};
        std::array<unsigned char, 64> their_signed_signature{};
        std::array<unsigned char, 32> their_onetime_public{};
        bool has_onetime = false;

        bool device_ok = hex_to_bin(their_device_public_hex, their_device_public.data(), crypto_sign_PUBLICKEYBYTES);
        bool identity_ok = hex_to_bin(their_identity_public_hex, their_identity_public.data(),
                                      crypto_sign_PUBLICKEYBYTES);
        bool signed_ok = hex_to_bin(their_signed_public_hex, their_signed_public.data(), crypto_sign_PUBLICKEYBYTES);
        bool signature_ok = hex_to_bin(their_signed_signature_hex, their_signed_signature.data(), crypto_sign_BYTES);

        // Only process one-time key if it exists and is not NULL
        if (bundle.contains("one_time_key") && !bundle["one_time_key"].is_null()) {
            std::string their_onetime_public_hex = bundle["one_time_key"];
            bool onetime_ok = hex_to_bin(their_onetime_public_hex, their_onetime_public.data(),
                                         crypto_sign_PUBLICKEYBYTES);
            std::cout << "One-time key conversion: " << (onetime_ok ? "success" : "failed") << std::endl;
            if (onetime_ok) {
                has_onetime = true;
            }
        }

        if (!device_ok || !identity_ok || !signed_ok || !signature_ok) {
            throw std::runtime_error("Failed to decode key bundle data");
        }

        std::array<unsigned char, 32> pk_eph{};
        auto sk_buffer_eph = SecureMemoryBuffer::create(ENC_SECRET_KEY_LEN);
        crypto_box_keypair(pk_eph.data(), sk_buffer_eph->data());

        // Convert QByteArray to std::array for my device public key
        std::array<unsigned char, 32> my_device_public{};
        memcpy(my_device_public.data(), pk_device.constData(), 32);

        // Create a new KeyBundle
        auto *key_bundle = new SendingKeyBundle(
            my_device_public,
            pk_eph,
            std::shared_ptr<SecureMemoryBuffer>(sk_buffer_eph.release()),
            their_device_public,
            their_signed_public,
            has_onetime ? their_onetime_public : std::array<unsigned char, 32>{},
            their_signed_signature
        );

        bundles.push_back(key_bundle);
    }

    // Convert their identity public key to binary
    std::array<unsigned char, 32> their_identity_public{};
    if (!hex_to_bin(their_identity_public_hex, their_identity_public.data(), crypto_sign_PUBLICKEYBYTES)) {
        throw std::runtime_error("Failed to decode their identity public key");
    }

    return bundles;
}

void post_handshake_device(
    const unsigned char *recipient_device_key_public,
    const unsigned char *recipient_signed_prekey_public,
    const unsigned char *recipient_signed_prekey_signature,
    const unsigned char *recipient_onetime_prekey_public,
    const unsigned char *my_ephemeral_key_public
) {
    auto my_device_key_public = get_public_key("device");
    json body = {
        {"username", SessionTokenManager::instance().getUsername()},
        {"recipient_device_key", bin2hex(recipient_device_key_public, crypto_box_PUBLICKEYBYTES)},
        {"recipient_signed_public_prekey", bin2hex(recipient_signed_prekey_public, crypto_box_PUBLICKEYBYTES)},
        {
            "recipient_signed_public_prekey_signature",
            bin2hex(recipient_signed_prekey_signature, crypto_sign_BYTES)
        },
        {"initiator_ephemeral_public_key", bin2hex(my_ephemeral_key_public, crypto_box_PUBLICKEYBYTES)},
        {
            "initiator_device_public_key",
            bin2hex(reinterpret_cast<const unsigned char *>(my_device_key_public.constData()),
                    crypto_box_PUBLICKEYBYTES)
        },
    };

    // Only add one-time prekey if it exists
    if (recipient_onetime_prekey_public != nullptr) {
        body["recipient_onetime_public_prekey"] = bin2hex(recipient_onetime_prekey_public, crypto_box_PUBLICKEYBYTES);
    }

    post("/handshake", body);
}

std::vector<std::tuple<std::string, KeyBundle *> > get_handshake_backlog() {
    json response;
    try {
        response = get("/incomingHandshakes");
    } catch (const std::exception &e) {
        return std::vector<std::tuple<std::string, KeyBundle *> >();
    }

    std::cout << "Raw response: " << response.dump() << std::endl;
    std::cout << "Response keys: ";
    for (auto &[key, value]: response.items()) {
        std::cout << key << " ";
    }
    std::cout << std::endl;

    std::vector<std::tuple<std::string, KeyBundle *> > bundles;

    // Check if data array exists
    if (!response.contains("data") || !response["data"].is_array()) {
        std::cout << "No handshakes in response" << std::endl;
        return bundles;
    }

    for (const auto &handshake: response["data"]) {
        std::array<unsigned char, 32> initator_dev_key{};
        std::array<unsigned char, 32> initiator_eph_pub{};
        std::array<unsigned char, 32> recip_onetime_pub{};
        bool has_onetime = false;

        std::string dev_key_str = handshake["initiator_device_public_key"].get<std::string>();
        std::string eph_pub_str = handshake["initiator_ephemeral_public_key"].get<std::string>();
        std::string username = handshake["username"].get<std::string>();

        bool success = hex_to_bin(dev_key_str, initator_dev_key.data(), crypto_box_PUBLICKEYBYTES) &&
                       hex_to_bin(eph_pub_str, initiator_eph_pub.data(), crypto_box_PUBLICKEYBYTES);
        if (!success) {
            throw std::runtime_error("Failed to decode handshake backlog data");
        }

        // Only process one-time prekey if it exists in the response
        if (handshake.contains("recipient_onetime_public_prekey")) {
            std::string onetime_pub_str = handshake["recipient_onetime_public_prekey"].get<std::string>();
            if (!hex_to_bin(onetime_pub_str, recip_onetime_pub.data(), crypto_box_PUBLICKEYBYTES)) {
                throw std::runtime_error("Failed to decode one-time prekey data");
            }
            has_onetime = true;
        }

        auto device_key = get_public_key("device");
        std::array<unsigned char, 32> my_device_public{};
        memcpy(my_device_public.data(), device_key.constData(), 32);

        auto new_bundle = new ReceivingKeyBundle(
            initator_dev_key,
            initiator_eph_pub,
            my_device_public,
            has_onetime ? recip_onetime_pub : std::array<unsigned char, 32>{}
        );

        bundles.push_back(std::make_tuple(username, new_bundle));
    }

    return bundles;
}

// Version with signed prekey (original behavior)
void post_new_keybundles(
    std::tuple<QByteArray, std::unique_ptr<SecureMemoryBuffer> > device_keypair,
    std::tuple<unsigned char *, std::unique_ptr<SecureMemoryBuffer> > *signed_prekeypair,
    const std::vector<std::tuple<unsigned char *, std::unique_ptr<SecureMemoryBuffer>, unsigned char *> > &otks
) {
    auto [pk_device_q, sk_device] = std::move(device_keypair);

    // Create JSON payload with one-time keys
    json body = {
        {"one_time_keys", json::array()}
    };

    std::cout << "DEBUG: post_new_keybundles called" << std::endl;
    std::cout << "DEBUG: signed_prekeypair pointer = " << (signed_prekeypair ? "NOT NULL" : "NULL") << std::endl;

    // Only include signed prekey if pointer is not nullptr
    if (signed_prekeypair != nullptr) {
        auto [pk_signed, sk_signed] = std::move(*signed_prekeypair);

        std::cout << "DEBUG: pk_signed pointer = " << (pk_signed ? "NOT NULL" : "NULL") << std::endl;
        if (pk_signed) {
            std::cout << "DEBUG: pk_signed value = " << bin2hex(pk_signed, 32) << std::endl;
        }

        // Only sign if pk_signed is not nullptr
        if (pk_signed != nullptr) {
            std::cout << "DEBUG: Adding signed prekey to JSON body" << std::endl;

            //sign the public key with device key
            unsigned char signature[crypto_sign_BYTES];
            crypto_sign_detached(signature, nullptr, pk_signed, crypto_sign_PUBLICKEYBYTES, sk_device->data());

            // Convert signature to hex string
            std::string signature_hex = bin2hex(signature, crypto_sign_BYTES);
            std::string signed_prekey_pub_hex = bin2hex(pk_signed, crypto_box_PUBLICKEYBYTES);

            body["signedpre_key"] = signed_prekey_pub_hex;
            body["signedpk_signature"] = signature_hex;

            std::cout << "DEBUG: signed_prekey_pub_hex = " << signed_prekey_pub_hex << std::endl;
        } else {
            std::cout << "DEBUG: pk_signed is NULL, not adding to body" << std::endl;
        }
    } else {
        std::cout << "DEBUG: signed_prekeypair is NULL, not adding to body" << std::endl;
    }

    for (const auto &[pk, sk, nonce]: otks) {
        body["one_time_keys"].push_back(bin2hex(pk, crypto_box_PUBLICKEYBYTES));
    }

    std::cout << "DEBUG: Final JSON body = " << body.dump() << std::endl;
    post("/updateKeybundle", body);
}

// Version without signed prekey (new behavior)
void post_new_keybundles(
    std::tuple<QByteArray, std::unique_ptr<SecureMemoryBuffer> > device_keypair,
    const std::vector<std::tuple<unsigned char *, std::unique_ptr<SecureMemoryBuffer>, unsigned char *> > &otks
) {
    auto [pk_device_q, sk_device] = std::move(device_keypair);

    // Create JSON payload with only one-time keys
    json body = {
        {"one_time_keys", json::array()}
    };

    for (const auto &[pk, sk, nonce]: otks) {
        body["one_time_keys"].push_back(bin2hex(pk, crypto_box_PUBLICKEYBYTES));
    }
    post("/updateKeybundle", body);
}

std::string post_upload_file(std::vector<unsigned char> encrypted_bytes) {
    const json body = {
        {"encrypted_bytes", encrypted_bytes}
    };

    const json response = post("/uploadFile", body);
    return response["data"]["file_id"];
}

std::vector<std::string> get_devices() {
    const json response = get("/getDevices");
    return response["data"];
}

std::vector<unsigned char> get_encrypted_file(std::string uuid) {
    try {
        json response = get("/downloadFile/" + uuid);

        // Debug: Print the raw response to see what we're actually getting
        std::cout << "Raw JSON response: " << response.dump() << std::endl;
        std::cout << "Response keys: ";
        for (auto &[key, value]: response.items()) {
            std::cout << key << " ";
        }
        std::cout << std::endl;

        // Check if the response contains data.encrypted_bytes field
        if (!response.contains("data") || !response["data"].contains("encrypted_bytes") || !response["data"][
                "encrypted_bytes"].is_string()) {
            std::cout << "No encrypted_bytes hex string in response data for UUID: " << uuid << std::endl;
            return std::vector<unsigned char>();
        }

        // Parse the encrypted_bytes hex string
        std::string hex_data = response["data"]["encrypted_bytes"].get<std::string>();
        std::cout << "Hex data length: " << hex_data.length() << std::endl;
        std::cout << "First 100 chars of hex: " << hex_data.substr(0, 100) << std::endl;

        size_t binary_size = hex_data.length() / 2;

        if (binary_size == 0) {
            std::cout << "Empty encrypted_bytes hex string for UUID: " << uuid << std::endl;
            return std::vector<unsigned char>();
        }

        std::cout << "Binary size will be: " << binary_size << " bytes" << std::endl;

        std::vector<unsigned char> file_data(binary_size);
        size_t bin_len;
        const char *hex_end;

        // Use libsodium's hex2bin function for more reliable hex parsing
        if (sodium_hex2bin(file_data.data(), file_data.size(),
                           hex_data.c_str(), hex_data.length(),
                           nullptr, &bin_len, &hex_end) != 0) {
            std::cout << "Failed to convert hex to binary using sodium_hex2bin for UUID: " << uuid << std::endl;
            std::cout << "Hex string length: " << hex_data.length() << std::endl;
            std::cout << "Expected binary size: " << binary_size << std::endl;
            return std::vector<unsigned char>();
        }

        // Resize vector to actual parsed length (might be smaller if hex had whitespace)
        file_data.resize(bin_len);

        std::cout << "Successfully converted hex to binary using sodium" << std::endl;
        std::cout << "Downloaded file data, size: " << file_data.size() << " bytes" << std::endl;
        std::cout << "First 20 bytes: ";
        for (size_t i = 0; i < std::min((size_t) 20, file_data.size()); i++) {
            printf("%02x ", file_data[i]);
        }
        std::cout << std::endl;

        return file_data;
    } catch (const std::exception &e) {
        std::cout << "Failed to download file " << uuid << ": " << e.what() << std::endl;
        return std::vector<unsigned char>();
    }
}

// file uuid : ciphertext
std::map<std::string, std::vector<unsigned char> > get_encrypted_file_metadata(std::vector<std::string> uuids) {
    json body = {
        {"file_ids", json::array()}
    };

    for (auto uuid: uuids) {
        body["file_ids"].push_back(uuid);
    }

    std::cout << "DEBUG: Requesting metadata for " << uuids.size() << " UUIDs" << std::endl;
    json response = post("/getFilesMetadata", body);

    std::map<std::string, std::vector<unsigned char> > files_metadata;

    // Check if response contains data and metadata
    if (!response.contains("data") || !response["data"].contains("metadata")) {
        std::cerr << "Invalid response format for file metadata" << std::endl;
        return files_metadata;
    }

    std::cout << "DEBUG: Server returned metadata for " << response["data"]["metadata"].size() << " files" << std::endl;

    for (const auto &file_data: response["data"]["metadata"]) {
        if (!file_data.contains("file_id") || !file_data.contains("encrypted_metadata")) {
            std::cerr << "Missing uuid or encrypted_metadata in file data" << std::endl;
            continue;
        }

        std::string uuid = file_data["file_id"].get<std::string>();
        std::string hex_metadata = file_data["encrypted_metadata"].get<std::string>();

        std::cout << "\n--- DEBUG: Processing metadata for UUID: " << uuid << " ---" << std::endl;
        std::cout << "Hex metadata from server: " << hex_metadata << std::endl;
        std::cout << "Hex metadata length: " << hex_metadata.length() << " chars" << std::endl;

        size_t binary_size = hex_metadata.length() / 2;
        if (binary_size == 0) {
            std::cerr << "Empty encrypted metadata for file " << uuid << std::endl;
            continue;
        }

        std::cout << "Expected binary size: " << binary_size << " bytes" << std::endl;
        std::vector<unsigned char> binary_metadata(binary_size);

        if (hex_to_bin(hex_metadata, binary_metadata.data(), binary_size)) {
            std::cout << "Successfully converted hex to binary" << std::endl;
            std::cout << "Binary metadata first 16 bytes: ";
            for (size_t i = 0; i < std::min((size_t)16, binary_metadata.size()); i++) {
                printf("%02x ", binary_metadata[i]);
            }
            std::cout << std::endl;
            
            files_metadata[uuid] = std::move(binary_metadata);
        } else {
            std::cerr << "Failed to convert hex metadata to binary for file " << uuid << std::endl;
        }
    }

    std::cout << "DEBUG: Returning metadata for " << files_metadata.size() << " files" << std::endl;
    return files_metadata;
}
