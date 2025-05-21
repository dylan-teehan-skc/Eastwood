#include "DoubleRatchet.h"
#include <cstring>
#include <sodium.h>
#include <stdexcept>

DoubleRatchet::DoubleRatchet(const unsigned char* x3dh_root_key,
              const unsigned char* remote_public_signed_prekey,
              const unsigned char* local_public_ephemeral,
              const unsigned char* local_private_ephemeral) {
    // Initialize key arrays with zeros
    memset(send_key, 0, crypto_kdf_KEYBYTES);
    memset(recv_key, 0, crypto_kdf_KEYBYTES);
    
    memcpy(local_dh_public, local_public_ephemeral, crypto_box_PUBLICKEYBYTES);
    memcpy(local_dh_private, local_private_ephemeral, crypto_box_PUBLICKEYBYTES);
    memcpy(root_key, x3dh_root_key, crypto_box_PUBLICKEYBYTES);
    memcpy(remote_dh_public, remote_public_signed_prekey, crypto_box_PUBLICKEYBYTES);
}

unsigned char* DoubleRatchet::message_send() {
    // Generate new DH keypair
    crypto_kx_keypair(local_dh_public, local_dh_private);

    unsigned char shared_secret[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared_secret, local_dh_private, remote_dh_public) != 0) {
        throw std::runtime_error("Error in crypto_scalarmult");
    }

    // Combine root_key and shared_secret
    unsigned char combined[64];
    memcpy(combined, root_key, crypto_kdf_KEYBYTES);
    memcpy(combined + crypto_kdf_KEYBYTES, shared_secret, crypto_scalarmult_BYTES);

    unsigned char master_key[crypto_kdf_KEYBYTES];

    // Hash combined keys to get new master key
    crypto_generichash(master_key, crypto_kdf_KEYBYTES, combined, sizeof combined, NULL, 0);

    // Context string must be exactly 8 bytes
    const char *ctx = "DRATCHT1";

    // Derive new root_key and send_key
    if (crypto_kdf_derive_from_key(root_key, crypto_kdf_KEYBYTES, 1, ctx, master_key) != 0) {
        throw std::runtime_error("Failed to derive new root key");
    }

    if (crypto_kdf_derive_from_key(send_key, crypto_kdf_KEYBYTES, 2, ctx, master_key) != 0) {
        throw std::runtime_error("Failed to derive send chain key");
    }

    unsigned char kdf_output[64];  // 64 bytes output

    crypto_generichash(kdf_output, sizeof kdf_output,
                       send_key, crypto_kdf_KEYBYTES,
                       NULL, 0);

    unsigned char* message_key = new unsigned char[crypto_kdf_KEYBYTES];
    memcpy(message_key, kdf_output, crypto_kdf_KEYBYTES);

    unsigned char new_send_chain_key[crypto_kdf_KEYBYTES];
    memcpy(new_send_chain_key, kdf_output + crypto_kdf_KEYBYTES, crypto_kdf_KEYBYTES);

    memcpy(send_key, new_send_chain_key, crypto_kdf_KEYBYTES);
    return message_key;

    //encrypt file and send new public key with payload

    //TODO: potentially make message key smart pointer, potential memory leak
}

unsigned char* DoubleRatchet::message_receive(const unsigned char* new_remote_public_key) {
    // Update remote public key from parameter
    memcpy(remote_dh_public, new_remote_public_key, crypto_kx_PUBLICKEYBYTES);

    //compute shared secret
    unsigned char shared_secret[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared_secret, local_dh_private, remote_dh_public) != 0) {
        throw std::runtime_error("Error in crypto_scalarmult");
    }

    // Combine root_key and shared_secret
    unsigned char combined[64];
    memcpy(combined, root_key, crypto_kdf_KEYBYTES);
    memcpy(combined + crypto_kdf_KEYBYTES, shared_secret, crypto_scalarmult_BYTES);

    unsigned char master_key[crypto_kdf_KEYBYTES];

    // Hash combined keys to get new master key
    crypto_generichash(master_key, crypto_kdf_KEYBYTES, combined, sizeof combined, NULL, 0);

    // Context string must be exactly 8 bytes
    const char *ctx = "DRATCHT1";

    // Derive new root_key and recv_key
    if (crypto_kdf_derive_from_key(root_key, crypto_kdf_KEYBYTES, 1, ctx, master_key) != 0) {
        throw std::runtime_error("Failed to derive new root key");
    }

    if (crypto_kdf_derive_from_key(recv_key, crypto_kdf_KEYBYTES, 2, ctx, master_key) != 0) {
        throw std::runtime_error("Failed to derive recv chain key");
    }

    unsigned char kdf_output[64];  // 64 bytes output

    crypto_generichash(kdf_output, sizeof kdf_output,
                       recv_key, crypto_kdf_KEYBYTES,
                       NULL, 0);

    unsigned char* message_key = new unsigned char[crypto_kdf_KEYBYTES];
    memcpy(message_key, kdf_output, crypto_kdf_KEYBYTES);

    unsigned char new_recv_chain_key[crypto_kdf_KEYBYTES];
    memcpy(new_recv_chain_key, kdf_output + crypto_kdf_KEYBYTES, crypto_kdf_KEYBYTES);

    memcpy(recv_key, new_recv_chain_key, crypto_kdf_KEYBYTES);
    return message_key;
}

const unsigned char* DoubleRatchet::get_public_key() const {
    return local_dh_public;
}

void DoubleRatchet::print_state() const {
    // This will require bin2hex implementation or including iostream
    // For now, we'll just have an empty implementation
}
