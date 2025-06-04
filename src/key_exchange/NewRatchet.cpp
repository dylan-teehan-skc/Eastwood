//
// Created by Josh Sloggett on 30/05/2025.
//

#include "NewRatchet.h"
#include <sstream>
#include "XChaCha20-Poly1305.h"
#include "src/keys/kek_manager.h"
#include "src/sql/queries.h"
#include "src/key_exchange/utils.h"
#include <sodium.h>
#include <memory>
#include <iostream>

// other key is initiator ephemeral for recipient
// other key is receiver signed prekey for initiator
NewRatchet::NewRatchet(const std::array<unsigned char, 32>shared_secret, const std::array<unsigned char, 32>other_key) {
    memcpy(root_key.data(), shared_secret.data(), 32);

    set_up_initial_state_for_recipient(other_key);

    set_up_initial_chain_keys();
}

NewRatchet::NewRatchet(const std::array<unsigned char, 32> shared_secret, const std::array<unsigned char, 32> other_key,
                       const std::array<unsigned char, 32> my_ephemeral_public, const std::shared_ptr<SecureMemoryBuffer> &my_ephemeral_private) {
    memcpy(root_key.data(), shared_secret.data(), 32);

    set_up_initial_state_for_initiator(other_key, my_ephemeral_public, my_ephemeral_private);

    set_up_initial_chain_keys();
}

//serialised
NewRatchet::NewRatchet(const std::vector<unsigned char> &serialised_ratchet) {
    std::istringstream in(std::string(
        reinterpret_cast<const char*>(serialised_ratchet.data()),
        serialised_ratchet.size()
    ));
    deserialise(in);
}

void NewRatchet::set_up_initial_state_for_initiator(const std::array<unsigned char, 32> recipient_signed_public,
                                                    const std::array<unsigned char, 32> my_ephemeral_public,
                                                    std::shared_ptr<SecureMemoryBuffer> my_ephemeral_private) {
    reversed = false;
    memcpy(local_dh_public.data(), my_ephemeral_public.data(), 32);
    local_dh_priv = SecureMemoryBuffer::create(32);
    memcpy(local_dh_priv->data(), my_ephemeral_private->data(), 32);
    memcpy(remote_dh_public.data(), recipient_signed_public.data(), 32);
}

void NewRatchet::set_up_initial_state_for_recipient(const std::array<unsigned char, 32> initiator_ephemeral_public) {
    reversed = true;
    //setup initial local dh pub priv
    auto [public_signed, sk_signed] = get_decrypted_keypair("signed");
    local_dh_priv = std::move(sk_signed);
    memcpy(local_dh_public.data(), public_signed.constData(), 32);

    //remote dh pub
    memcpy(remote_dh_public.data(), initiator_ephemeral_public.data(), 32);
};

void NewRatchet::set_up_initial_chain_keys() {
    auto dh_output = dh();

    std::array<unsigned char, 32> kdf_key;
    crypto_generichash(kdf_key.data(), sizeof(kdf_key), dh_output.get(), 32, nullptr, 0);

    // run kdf
    crypto_kdf_derive_from_key(
        send_chain.key.data(),
        32,
        0,
        "DRXsend1", // one side send is another recv
        kdf_key.data()
    );

    crypto_kdf_derive_from_key(
        receive_chain.key.data(),
        32,
        1,
        "DRXrecv1", // one side recv is another send
        kdf_key.data()
    );

    crypto_kdf_derive_from_key(
        root_key.data(),
        32,
        2,
        "DRXroot1",
        kdf_key.data()
    );

    // Swap send/receive chains for responder
    if (reversed) {
        std::array<unsigned char, 32> tmp;
        memcpy(tmp.data(), send_chain.key.data(), 32);
        memcpy(send_chain.key.data(), receive_chain.key.data(), 32);
        memcpy(receive_chain.key.data(), tmp.data(), 32);
    }

    due_to_send_new_dh = false;
}

void NewRatchet::dh_ratchet_step(const bool received_new_dh) {
    auto dh_output = dh();

    std::array<unsigned char, 32> kdf_key;
    crypto_generichash(kdf_key.data(), sizeof(kdf_key), dh_output.get(), 32, nullptr, 0);

    std::array<unsigned char, 32> new_root_key;
    crypto_kdf_derive_from_key(
        new_root_key.data(),
        32,
        0,
        "DHRatchet",
        kdf_key.data()
    );

    std::array<unsigned char, 32> new_chain_key;
    crypto_kdf_derive_from_key(
        new_chain_key.data(),
        32,
        1,
        "DHRatchet",
        kdf_key.data()
    );

    memcpy(root_key.data(), new_root_key.data(), 32);

    if (received_new_dh) {
        // When receiving a new DH key, update the receive chain
        memcpy(receive_chain.key.data(), new_chain_key.data(), 32);
        receive_chain.index = 0;

        // Generate new local DH keypair for future sends
        generate_new_local_dh_keypair();
        
        // Derive new send chain from updated root key and new DH
        auto new_dh_output = dh();
        std::array<unsigned char, 32> new_kdf_key;
        crypto_generichash(new_kdf_key.data(), new_kdf_key.size(), new_dh_output.get(), 32, nullptr, 0);
        
        std::array<unsigned char, 32> updated_root_key;
        crypto_kdf_derive_from_key(
            updated_root_key.data(),
            32,
            0,
            "DHRatchet",
            new_kdf_key.data()
        );
        
        std::array<unsigned char, 32> new_send_chain_key;
        crypto_kdf_derive_from_key(
            new_send_chain_key.data(),
            32,
            1,
            "DHRatchet",
            new_kdf_key.data()
        );
        
        memcpy(root_key.data(), updated_root_key.data(), 32);
        memcpy(send_chain.key.data(), new_send_chain_key.data(), 32);
        send_chain.index = 0;

    } else {
        // When sending a new DH key, update the send chain
        memcpy(send_chain.key.data(), new_chain_key.data(), 32);
        send_chain.index = 0;
    }
}

void NewRatchet::generate_new_local_dh_keypair() {
    crypto_box_keypair(local_dh_public.data(), local_dh_priv->data());
};

std::unique_ptr<unsigned char[]> NewRatchet::dh() const {
    auto result = std::make_unique<unsigned char[]>(32);
    if (crypto_scalarmult(result.get(), local_dh_priv->data(), remote_dh_public.data()) != 0) {
        throw std::runtime_error("Failed to perform dh");
    }
    return result;
}

std::tuple<std::array<unsigned char,32>, MessageHeader> NewRatchet::advance_send() {

    if (due_to_send_new_dh) {
        dh_ratchet_step(false); // we are sending the new dh not receiving
        due_to_send_new_dh = false;
    }

    auto [raw_id, message_header] = progress_sending_ratchet();
    std::array<unsigned char, 32> device_id;
    std::memcpy(device_id.data(), raw_id.data(), 32);

    return std::make_tuple(device_id, message_header);
}

std::array<unsigned char, 32> NewRatchet::advance_receive(const MessageHeader header) {

    // if new dh public
    if (memcmp(remote_dh_public.data(), header.dh_public.data(), 32) != 0) {
        int skipped_count = receive_chain.index;
        // if we need to forward cache keys due to prev chain length being longer than expected
        for (int i = header.prev_chain_length; i < skipped_count; ++i) {
            auto message_key = progress_receive_ratchet();
            skipped_keys[i] = message_key;
        }
        memcpy(remote_dh_public.data(), header.dh_public.data(), 32);
        dh_ratchet_step(true); // true as we received the new dh
        due_to_send_new_dh = true; // Next send should use new DH keys
    }

    // if we've already computed the key
    if (header.message_index < receive_chain.index) {
        if (skipped_keys.find(header.message_index) == skipped_keys.end()) {
            throw std::runtime_error("Key not found in backlog");
        }
        auto key = skipped_keys[header.message_index];
        skipped_keys.erase(header.message_index);
        return key;
    }

    // get the key normally
    for (int i = receive_chain.index; i <= header.message_index; i++) {
        const auto message_key = progress_receive_ratchet();

        if (i == header.message_index) {
            receive_chain.index = i + 1;
            return message_key;
        }
        skipped_keys[i] = message_key;
    }

    throw std::runtime_error("Unexpected error in advance_receive");
}

std::array<unsigned char, 32> NewRatchet::progress_receive_ratchet() {
    std::array<unsigned char, 32> msg_key{};
    std::array<unsigned char, 32> next_receive_key{};
    const char *ctx = "DRSndKey"; // Use same context as sender

    crypto_kdf_derive_from_key(msg_key.data(), 32, 0, ctx, receive_chain.key.data());
    crypto_kdf_derive_from_key(next_receive_key.data(), 32, 1, ctx, receive_chain.key.data());

    memcpy(receive_chain.key.data(), next_receive_key.data(), 32);
    return msg_key; //ptr
}

std::tuple<std::array<unsigned char, 32>, MessageHeader> NewRatchet::progress_sending_ratchet() {
    std::array<unsigned char, 32> message_key{};
    std::array<unsigned char, 32> next_send_key{};
    const char *ctx = "DRSndKey"; // Use same context as in advance_send

    auto header = MessageHeader();
    memcpy(header.dh_public.data(), local_dh_public.data(), 32);
    header.message_index = send_chain.index;
    header.prev_chain_length = receive_chain.index; // Set previous chain length

    crypto_kdf_derive_from_key(message_key.data(), 32, 0, ctx, send_chain.key.data());
    crypto_kdf_derive_from_key(next_send_key.data(), 32, 1, ctx, send_chain.key.data());

    memcpy(send_chain.key.data(), next_send_key.data(), 32);
    send_chain.index++;

    return std::make_tuple(message_key, header);
}

//remove this is for tesitng
const std::array<unsigned char, 32> NewRatchet::get_current_dh_public() const {
    return local_dh_public;
}

std::tuple<int, int> NewRatchet::get_chain_lengths() {
    return std::make_tuple(send_chain.index, receive_chain.index);
}

void NewRatchet::serialise(std::ostream &out) const {
    out.write(reinterpret_cast<const char*>(root_key.data()), 32);
    out.write(reinterpret_cast<const char*>(local_dh_public.data()), 32);
    out.write(reinterpret_cast<const char*>(local_dh_priv->data()), 32);
    out.write(reinterpret_cast<const char*>(remote_dh_public.data()), 32);

    out.write(reinterpret_cast<const char*>(send_chain.key.data()), 32);
    out.write(reinterpret_cast<const char*>(&send_chain.index), sizeof(send_chain.index));

    out.write(reinterpret_cast<const char*>(receive_chain.key.data()), 32);
    out.write(reinterpret_cast<const char*>(&receive_chain.index), sizeof(receive_chain.index));

    // serialize skipped_keys count
    uint32_t skipped_count = skipped_keys.size();
    out.write(reinterpret_cast<const char*>(&skipped_count), sizeof(skipped_count));
    for (const auto &pair : skipped_keys) {
        out.write(reinterpret_cast<const char*>(&pair.first), sizeof(pair.first));
        out.write(reinterpret_cast<const char*>(pair.second.data()), 32);
    }

    out.write(reinterpret_cast<const char*>(&due_to_send_new_dh), sizeof(due_to_send_new_dh));
    out.write(reinterpret_cast<const char*>(&reversed), sizeof(reversed));
    out.write(reinterpret_cast<const char*>(&prev_chain_length), sizeof(prev_chain_length));
}

void NewRatchet::deserialise(std::istream &in) {
    in.read(reinterpret_cast<char*>(root_key.data()), 32);
    in.read(reinterpret_cast<char*>(local_dh_public.data()), 32);

    unsigned char priv[32];
    in.read(reinterpret_cast<char*>(priv), 32);

    // Now create or reuse your buffer, copying raw data into it
    local_dh_priv = SecureMemoryBuffer::create(32);
    memcpy(local_dh_priv->data(), priv, 32);

    in.read(reinterpret_cast<char*>(remote_dh_public.data()), 32);

    in.read(reinterpret_cast<char*>(send_chain.key.data()), 32);
    in.read(reinterpret_cast<char*>(&send_chain.index), sizeof(send_chain.index));

    in.read(reinterpret_cast<char*>(receive_chain.key.data()), 32);
    in.read(reinterpret_cast<char*>(&receive_chain.index), sizeof(receive_chain.index));

    uint32_t skipped_count;
    in.read(reinterpret_cast<char*>(&skipped_count), sizeof(skipped_count));
    
    skipped_keys.clear();
    for (uint32_t i = 0; i < skipped_count; ++i) {
        int key;
        std::array<unsigned char, 32> val{};
        in.read(reinterpret_cast<char*>(&key), sizeof(key));
        in.read(reinterpret_cast<char*>(val.data()), 32);
        skipped_keys[key] = val;
    }

    in.read(reinterpret_cast<char*>(&due_to_send_new_dh), sizeof(due_to_send_new_dh));
    in.read(reinterpret_cast<char*>(&reversed), sizeof(reversed));
    in.read(reinterpret_cast<char*>(&prev_chain_length), sizeof(prev_chain_length));
}

void NewRatchet::save(const std::string& username, const std::array<unsigned char, 32>& device_id) {
    std::ostringstream oss(std::ios::binary);
    serialise(oss);

    std::string str = oss.str();
    QByteArray bytes(str.data(), static_cast<int>(str.size()));

    auto nonce_data = std::make_unique<unsigned char[]>(CHA_CHA_NONCE_LEN);
    randombytes_buf(nonce_data.get(), CHA_CHA_NONCE_LEN);

    auto nonce_key = std::make_unique<unsigned char[]>(CHA_CHA_NONCE_LEN);
    randombytes_buf(nonce_key.get(), CHA_CHA_NONCE_LEN);

    auto encryption_key = SecureMemoryBuffer::create(32);
    crypto_stream_chacha20_keygen(encryption_key->data());

    auto copy_encryption_key = SecureMemoryBuffer::create(32);
    memcpy(copy_encryption_key->data(), encryption_key->data(), 32);

    auto encrypted_data = encrypt_bytes(bytes, std::move(copy_encryption_key), nonce_data.get());
    auto encrypted_encryption_key = encrypt_symmetric_key(encryption_key, nonce_key.get());

    save_ratchet_and_key_by_username_device(username, device_id, encrypted_data, nonce_data.get(), std::move(encrypted_encryption_key), nonce_key.get());
}






