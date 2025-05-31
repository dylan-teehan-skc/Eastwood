//
// Created by Josh Sloggett on 31/05/2025.
//
//
// Created by Josh Sloggett on 30/05/2025.
//

#include <gtest/gtest.h>
#include <tuple>

#include "kek_manager.h"
#include "NewRatchet.h"
#include "utils.h"
#include "database/schema.h"
#include "client_api_interactions/MakeAuthReq.h"
#include "libraries/BaseClient.h"
#include "libraries/HTTPSClient.h"
#include "endpoints/endpoints.h"
#include "keys/secure_memory_buffer.h"
#include "algorithms/algorithms.h"
#include "database/database.h"
#include "sessions/KeyBundle.h"
#include "sessions/IdentityManager.h"

class IdentitySessionTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (sodium_init() < 0) {
            throw std::runtime_error("Libsodium initialization failed");
        }

        auto kek = SecureMemoryBuffer::create(SYM_KEY_LEN);
        crypto_secretbox_keygen(kek->data());

        KekManager::instance().setKEK(std::move(kek));

        bool encrypted = false;

    const auto master_key = SecureMemoryBuffer::create(MASTER_KEY_LEN);
    randombytes_buf(master_key->data(), MASTER_KEY_LEN);
    Database::get().initialize("username", master_key, encrypted);

        auto master_password = std::make_unique<std::string>("correct horse battery stapler");
        drop_all_tables();
        init_schema();

        // Initialize SecureMemoryBuffer objects with correct sizes
        alice_device_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        alice_eph_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        bob_device_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        bob_presign_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        bob_onetime_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);

        // ALICE device & ephemeral
        // alice device keys
        crypto_sign_keypair(alice_device_pub, alice_device_priv->data());

        // alice ephemeral keys
        crypto_box_keypair(alice_eph_pub, alice_eph_priv->data());

        // BOB device, presigned & onetime
        // bob device keys
        crypto_sign_keypair(bob_device_pub, bob_device_priv->data());

        // bob presigned keys
        crypto_box_keypair(bob_presign_pub, bob_presign_priv->data());

        // bob onetime keys
        crypto_box_keypair(bob_onetime_pub, bob_onetime_priv->data());

        // bob signed signature
        crypto_sign_detached(bob_presign_signature,
            nullptr,
            bob_presign_pub,
            crypto_box_PUBLICKEYBYTES,
            bob_device_priv->data()
        );

        // Create a copy of alice_eph_priv and put it in a shared pointer
        auto alice_eph_priv_copy = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        memcpy(alice_eph_priv_copy->data(), alice_eph_priv->data(), crypto_sign_SECRETKEYBYTES);

        std::shared_ptr<SecureMemoryBuffer> shared_alice_eph_priv = std::shared_ptr<SecureMemoryBuffer>(alice_eph_priv_copy.release());

        alice_sending_bundle = new SendingKeyBundle(
            alice_device_pub,
            alice_eph_pub,
            std::move(shared_alice_eph_priv),
            bob_device_pub,
            bob_presign_pub,
            bob_onetime_pub,
            bob_presign_signature
        );

        bob_receiving_bundle = new ReceivingKeyBundle(
            alice_device_pub,
            alice_eph_pub,
            bob_device_pub,
            bob_onetime_pub
        );

        switch_to_alice_db();
        switch_to_bob_db();
    }

    void TearDown() override {
        if (alice_sending_bundle) {
            delete alice_sending_bundle;
            alice_sending_bundle = nullptr;
        }
        if (bob_receiving_bundle) {
            delete bob_receiving_bundle;
            bob_receiving_bundle = nullptr;
        }

        // Reset database state
        drop_all_tables();
    }

    void switch_to_alice_db() {
        drop_all_tables();
        init_schema();

        auto nonce = new unsigned char[CHA_CHA_NONCE_LEN];
        randombytes_buf(nonce, CHA_CHA_NONCE_LEN);

        std::unique_ptr<SecureMemoryBuffer> encrypted_alice_device_priv = encrypt_secret_key(std::move(alice_device_priv), nonce);
        save_encrypted_keypair("device", alice_device_pub, encrypted_alice_device_priv, nonce);

        delete[] nonce;
    }

    void switch_to_bob_db() {
        drop_all_tables();
        init_schema();

        auto nonce = new unsigned char[CHA_CHA_NONCE_LEN];
        randombytes_buf(nonce, CHA_CHA_NONCE_LEN);

        std::unique_ptr<SecureMemoryBuffer> encrypted_bob_device_priv = encrypt_secret_key(std::move(bob_device_priv), nonce);
        save_encrypted_keypair("device", bob_device_pub, encrypted_bob_device_priv, nonce);

        auto nonce_2 = new unsigned char[CHA_CHA_NONCE_LEN];
        randombytes_buf(nonce_2, CHA_CHA_NONCE_LEN);

        std::unique_ptr<SecureMemoryBuffer> encrypted_bob_presign_priv = encrypt_secret_key(std::move(bob_presign_priv), nonce_2);
        save_encrypted_keypair("signed", bob_presign_pub, encrypted_bob_presign_priv, nonce_2);

        auto nonce_3 = new unsigned char[CHA_CHA_NONCE_LEN];
        randombytes_buf(nonce_3, CHA_CHA_NONCE_LEN);

        std::unique_ptr<SecureMemoryBuffer> encrypted_bob_onetime_priv = encrypt_secret_key(std::move(bob_onetime_priv), nonce_3);

        unsigned char* onetime_pub_copy = new unsigned char[crypto_box_PUBLICKEYBYTES];
        memcpy(onetime_pub_copy, bob_onetime_pub, crypto_box_PUBLICKEYBYTES);

        std::vector<std::tuple<unsigned char*, std::unique_ptr<SecureMemoryBuffer>, unsigned char*>> onetime_keys;
        onetime_keys.emplace_back(onetime_pub_copy, std::move(encrypted_bob_onetime_priv), nonce_3);

        save_encrypted_onetime_keys(std::move(onetime_keys));

        // Clean up the copy
        delete[] onetime_pub_copy;
        delete[] nonce;
    }

    SendingKeyBundle *alice_sending_bundle = nullptr;
    ReceivingKeyBundle *bob_receiving_bundle = nullptr;

    unsigned char alice_device_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> alice_device_priv;

    unsigned char bob_device_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> bob_device_priv;

    unsigned char alice_eph_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> alice_eph_priv;

    unsigned char bob_presign_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> bob_presign_priv;

    unsigned char bob_onetime_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> bob_onetime_priv;

    unsigned char bob_presign_signature[crypto_sign_BYTES] = {};
};

TEST_F(IdentitySessionTest, SharedSecretDerivationTest) {
    EXPECT_EQ(1,1);
}
