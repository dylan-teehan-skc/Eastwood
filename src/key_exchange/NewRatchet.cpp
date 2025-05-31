//
// Created by Josh Sloggett on 30/05/2025.
//

#include "NewRatchet.h"

#include "src/sql/queries.h"

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
        dh_ratchet_step(false);
        due_to_send_new_dh = false;
    }

    auto message_key = new unsigned char[32];
    unsigned char next_send_key[32];
    const char *ctx = reversed ? "DRSndKey" : "DRRcvKey";

    auto header = new MessageHeader();
    memcpy(header->dh_public, local_dh_public, 32);
    header->message_index = send_chain.index;

    crypto_kdf_derive_from_key(
        message_key,
        32,
        0,
        ctx,
        send_chain.key
    );

    crypto_kdf_derive_from_key(
        next_send_key,
        32,
        1,
        ctx,
        send_chain.key
    );


    memcpy(send_chain.key, next_send_key, 32);
    send_chain.index = send_chain.index + 1;
    return std::make_tuple(message_key,header);
}

unsigned char* NewRatchet::advance_receive(MessageHeader* header) {

    if (memcmp(remote_dh_public, header->dh_public, 32) != 0) {
        memcpy(remote_dh_public, header->dh_public, 32);
        dh_ratchet_step(true); // true as we received the new dh
        due_to_send_new_dh = true;
    }

    auto message_key = new unsigned char[32];
    unsigned char next_receive_key[32];
    const char *ctx = reversed ? "DRRcvKey" : "DRSndKey";

    receive_chain.index = receive_chain.index + 1;

    crypto_kdf_derive_from_key(
        message_key,
        32,
        0,
        ctx,
        receive_chain.key
    );

    crypto_kdf_derive_from_key(
        next_receive_key,
        32,
        1,
        ctx,
        receive_chain.key
    );

    memcpy(receive_chain.key, next_receive_key, 32);
    return message_key;
}

//remove this is for tesitng
const unsigned char *NewRatchet::get_current_dh_public() const {
    return local_dh_public;
}

std::tuple<int, int> NewRatchet::get_chain_lengths() {
    return std::make_tuple(send_chain.index, receive_chain.index);
}




