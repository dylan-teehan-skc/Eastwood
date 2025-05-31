//
// Created by Josh Sloggett on 30/05/2025.
//

#include "NewRatchet.h"
#include "src/sql/queries.h"
#include <cstring>
#include <sodium.h>

// other key is initiator ephemeral for recipient
// other key is receiver signed prekey for initiator
NewRatchet::NewRatchet(const unsigned char *shared_secret, const unsigned char *other_key, bool is_sender) {
    memcpy(root_key, shared_secret, 32);

    if (is_sender) {
        set_up_initial_state_for_initiator(other_key);
    } else {
        set_up_initial_state_for_recipient(other_key);
    }

    set_up_initial_chain_keys();
}

//serialised
NewRatchet::NewRatchet(std::istream& in) {
    deserialise(in);
}

void NewRatchet::set_up_initial_state_for_initiator(const unsigned char *recipient_signed_public) {
    reversed = false;
    //setup initial local dh pub priv
    crypto_box_keypair(local_dh_public, local_dh_priv->data());

    //remote dh pub
    memcpy(remote_dh_public, recipient_signed_public, 32);
}

void NewRatchet::set_up_initial_state_for_recipient(const unsigned char *initiator_ephemeral_public) {
    reversed = true;
    //setup initial local dh pub priv
    auto [public_signed, sk_signed] = get_decrypted_keypair("signed");
    local_dh_priv = std::move(sk_signed);

    //remote dh pub
    memcpy(remote_dh_public, initiator_ephemeral_public, 32);
};

void NewRatchet::set_up_initial_chain_keys() {
    const auto dh_output = dh();

    unsigned char kdf_key[32];
    crypto_generichash(kdf_key, sizeof(kdf_key), dh_output, sizeof(dh_output), nullptr, 0);

    delete[] dh_output;

    // run kdf
    crypto_kdf_derive_from_key(
        send_chain.key,
        32,
        0,
        "DRXsend1", // one side send is another recv
        kdf_key
        );

    crypto_kdf_derive_from_key(
        receive_chain.key,
        32,
        1,
        "DRXrecv1", // one side recv is another send
        kdf_key
        );

    crypto_kdf_derive_from_key(
        root_key,
        32,
        2,
        "DRXroot1",
        kdf_key
        );
};

void NewRatchet::dh_ratchet_step(const bool received_new_dh) {
    unsigned char *dh_output = dh();

    unsigned char kdf_key[32];
    crypto_generichash(kdf_key, sizeof(kdf_key), dh_output, sizeof(dh_output), nullptr, 0);

    unsigned char new_root_key[32];
    crypto_kdf_derive_from_key(
        new_root_key,
        32,
        0,
        "DHRatchet",
        kdf_key
    );

    unsigned char new_chain_key[32];
    crypto_kdf_derive_from_key(
        new_chain_key,
        32,
        1,
        "DHRatchet",
        kdf_key
    );

    memcpy(root_key, new_root_key, 32);

    if (received_new_dh) {
        memcpy(receive_chain.key, new_chain_key, 32);

        generate_new_local_dh_keypair();
        memcpy(send_chain.key, root_key, 32);

        receive_chain.index = 0;
        send_chain.index = 0;

    } else {
        memcpy(send_chain.key, new_chain_key, 32);

        send_chain.index = 0;
    }

    delete[] dh_output;
};

void NewRatchet::generate_new_local_dh_keypair() {
    crypto_box_keypair(local_dh_public, local_dh_priv->data());
};

unsigned char* NewRatchet::dh() const {
    const auto result = new unsigned char[32];
    if (crypto_scalarmult(result, local_dh_priv->data(), remote_dh_public) != 0) {
        throw std::runtime_error("Failed to perform dh");
    };
    return result;
};

std::tuple<unsigned char*, MessageHeader*> NewRatchet::advance_send() {

    if (due_to_send_new_dh) {
        dh_ratchet_step(false); // we are sending the new dh not receiving
        due_to_send_new_dh = false;
    }

    return progress_sending_ratchet();
}

unsigned char* NewRatchet::advance_receive(const MessageHeader* header) {
    // if new dh public
    if (memcmp(remote_dh_public, header->dh_public, 32) != 0) {
        int skipped_count = receive_chain.index;
        // if we need to forward cache keys due to prev chain length being longer than expected
        for (int i = header->prev_chain_length; i < skipped_count; ++i) {
            skipped_keys[i] = progress_receive_ratchet();
        }
        memcpy(remote_dh_public, header->dh_public, 32);
        dh_ratchet_step(true); // true as we received the new dh
        due_to_send_new_dh = true;
    }

    // if we've already computed the key
    if (header->message_index < receive_chain.index) {
        if (header->message_index < receive_chain.index) {
            if (skipped_keys.find(header->message_index) == skipped_keys.end()) {
                throw std::runtime_error("Key not found in backlog");
            }
            auto key = skipped_keys[header->message_index];
            skipped_keys.erase(header->message_index);
            return key;
        }
    }

    // get the key normally
    for (int i = receive_chain.index; i <= header->message_index; i++) {
        const auto message_key = progress_receive_ratchet();
        if (i == header->message_index) {
            receive_chain.index = i + 1;
            return message_key;
        }
        skipped_keys[i] = message_key;
    }

    throw std::runtime_error("Unexpected error in advance_receive");
}

unsigned char* NewRatchet::progress_receive_ratchet() {
    auto msg_key = new unsigned char[32];
    unsigned char next_receive_key[32];
    const char *ctx = reversed ? "DRRcvKey" : "DRSndKey";

    crypto_kdf_derive_from_key(msg_key, 32, 0, ctx, receive_chain.key);
    crypto_kdf_derive_from_key(next_receive_key, 32, 1, ctx, receive_chain.key);

    memcpy(receive_chain.key, next_receive_key, 32);
    return msg_key;
}

std::tuple<unsigned char*, MessageHeader*> NewRatchet::progress_sending_ratchet() {
    auto message_key = new unsigned char[32];
    unsigned char next_send_key[32];
    const char *ctx = reversed ? "DRSndKey" : "DRRcvKey";

    auto header = new MessageHeader();
    memcpy(header->dh_public, local_dh_public, 32);
    header->message_index = send_chain.index;

    crypto_kdf_derive_from_key(message_key, 32, 0, ctx, send_chain.key);
    crypto_kdf_derive_from_key(next_send_key, 32, 1, ctx, send_chain.key);

    memcpy(send_chain.key, next_send_key, 32);
    send_chain.index = send_chain.index + 1;

    return std::make_tuple(message_key, header);
}

//remove this is for tesitng
const unsigned char *NewRatchet::get_current_dh_public() const {
    return local_dh_public;
}

std::tuple<int, int> NewRatchet::get_chain_lengths() {
    return std::make_tuple(send_chain.index, receive_chain.index);
}

void NewRatchet::serialise(std::ostream &out) const {
    out.write((char*)root_key, 32);
    out.write((char*)local_dh_public, 32);
    out.write((char*)local_dh_priv->data(), 32);
    out.write((char*)remote_dh_public, 32);

    out.write((char*)send_chain.key, 32);
    out.write((char*)&send_chain.index, sizeof(send_chain.index));

    out.write((char*)receive_chain.key, 32);
    out.write((char*)&receive_chain.index, sizeof(receive_chain.index));

    // serialize skipped_keys count
    uint32_t skipped_count = skipped_keys.size();
    out.write((char*)&skipped_count, sizeof(skipped_count));
    for (auto &pair : skipped_keys) {
        out.write((char*)&pair.first, sizeof(pair.first));
        out.write((char*)pair.second, 32);
    }

    out.write((char*)&due_to_send_new_dh, sizeof(due_to_send_new_dh));
    out.write((char*)&reversed, sizeof(reversed));
}

void NewRatchet::deserialise(std::istream &in) {
    in.read((char*)root_key, 32);
    in.read((char*)local_dh_public, 32);

    unsigned char priv[32];
    in.read(reinterpret_cast<char*>(priv), 32);

    // Now create or reuse your buffer, copying raw data into it
    local_dh_priv = SecureMemoryBuffer::create(32);
    memcpy(local_dh_priv->data(), priv, 32);

    in.read((char*)remote_dh_public, 32);

    in.read((char*)send_chain.key, 32);
    in.read((char*)&send_chain.index, sizeof(send_chain.index));

    in.read((char*)receive_chain.key, 32);
    in.read((char*)&receive_chain.index, sizeof(receive_chain.index));

    uint32_t skipped_count;
    in.read((char*)&skipped_count, sizeof(skipped_count));
    skipped_keys.clear();
    for (uint32_t i = 0; i < skipped_count; ++i) {
        int key;
        unsigned char *val = new unsigned char[32];
        in.read((char*)&key, sizeof(key));
        in.read((char*)val, 32);
        skipped_keys[key] = val;
    }

    in.read((char*)&due_to_send_new_dh, sizeof(due_to_send_new_dh));
    in.read((char*)&reversed, sizeof(reversed));
}





