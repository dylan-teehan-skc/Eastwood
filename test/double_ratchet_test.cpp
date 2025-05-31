//
// Created by Josh Sloggett on 30/05/2025.
//

#include <gtest/gtest.h>
#include <tuple>

#include "kek_manager.h"
#include "NewRatchet.h"
#include "utils.h"
#include "database/schema.h"
#include "src/key_exchange/DoubleRatchet.h"
#include "key_exchange/x3dh.h"
#include "key_exchange/XChaCha20-Poly1305.h"
#include "utils/ConversionUtils.h"
#include "utils/JsonParser.h"
#include "client_api_interactions/MakeAuthReq.h"
#include "client_api_interactions/MakeUnauthReq.h"
#include "libraries/BaseClient.h"
#include "libraries/HTTPSClient.h"
#include "endpoints/endpoints.h"
#include "keys/secure_memory_buffer.h"
#include "keys/session_token_manager.h"
#include "algorithms/algorithms.h"
#include "database/database.h"
#include "sessions/KeyBundle.h"
#include "sessions/IdentityManager.h"
#include "sessions/IdentitySession.h"

// Test fixture class for DoubleRatchet tests
class DoubleRatchetTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (sodium_init() < 0) {
            throw std::runtime_error("Libsodium initialization failed");
        }

        auto kek = SecureMemoryBuffer::create(SYM_KEY_LEN);
        crypto_secretbox_keygen(kek->data());

        KekManager::instance().setKEK(std::move(kek));

        bool encrypted = false;

        auto &db = Database::get();
        if (db.initialize("master key", encrypted)) {
            // Database initialized successfully
        } else {
            std::cerr << "Failed to initialize database." << std::endl;
        }

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

        // Unwrap alice_eph_priv and put it in a shared pointer
        std::shared_ptr<SecureMemoryBuffer> shared_alice_eph_priv = std::shared_ptr<SecureMemoryBuffer>(alice_eph_priv.release());

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

TEST_F(DoubleRatchetTest, SharedSecretDerivationTest) {
    switch_to_alice_db();
    unsigned char* shared_secret_alice = alice_sending_bundle->get_shared_secret();

    switch_to_bob_db();
    unsigned char* shared_secret_bob = bob_receiving_bundle->get_shared_secret();

    // Compare the actual values of the shared secrets
    EXPECT_EQ(memcmp(shared_secret_alice, shared_secret_bob, crypto_scalarmult_BYTES), 0);
}

TEST_F(DoubleRatchetTest, RatchetBothSidesTest) {
    // Initialize both parties
    switch_to_alice_db();

    NewRatchet alice(alice_sending_bundle->get_shared_secret(), bob_presign_pub, true);

    switch_to_bob_db();
    NewRatchet bob(bob_receiving_bundle->get_shared_secret(), alice_eph_pub, false);

    // Alice sends first message
    switch_to_alice_db();
    auto [alice_key1, header1] = alice.advance_send();
    switch_to_bob_db();
    auto bob_key1 = bob.advance_receive(header1);
    ASSERT_EQ(memcmp(alice_key1, bob_key1, 32), 0);

    // Bob responds
    auto [bob_key2, header2] = bob.advance_send();
    switch_to_alice_db();
    auto alice_key2 = alice.advance_receive(header2);
    ASSERT_EQ(memcmp(bob_key2, alice_key2, 32), 0);

    // Alice sends again (should trigger DH ratchet)
    auto [alice_key3, header3] = alice.advance_send();
    switch_to_bob_db();
    auto bob_key3 = bob.advance_receive(header3);
    ASSERT_EQ(memcmp(alice_key3, bob_key3, 32), 0);
}

TEST_F(DoubleRatchetTest, TwoMessageFromOneSideTest) {
    // Initialize both parties
    switch_to_alice_db();

    NewRatchet alice(alice_sending_bundle->get_shared_secret(), bob_presign_pub, true);

    switch_to_bob_db();
    NewRatchet bob(bob_receiving_bundle->get_shared_secret(), alice_eph_pub, false);

    // Alice sends first message
    switch_to_alice_db();
    auto [alice_key1, header1] = alice.advance_send();
    auto [alice_key2, header2] = alice.advance_send();
    auto [alice_key3, header3] = alice.advance_send();

    ASSERT_EQ(header1->message_index, 0);
    ASSERT_EQ(header2->message_index, 1);
    ASSERT_EQ(header3->message_index, 2);

    switch_to_bob_db();
    auto bob_key1 = bob.advance_receive(header1);
    auto bob_key2 = bob.advance_receive(header2);
    auto bob_key3 = bob.advance_receive(header3);

    //keys are the same
    ASSERT_EQ(memcmp(alice_key1, bob_key1, 32), 0);
    ASSERT_EQ(memcmp(alice_key2, bob_key2, 32), 0);
    ASSERT_EQ(memcmp(alice_key3, bob_key3, 32), 0);

}

TEST_F(DoubleRatchetTest, MessageIndexResetTest) {
    // Initialize both parties
    switch_to_alice_db();
    NewRatchet alice(alice_sending_bundle->get_shared_secret(), bob_presign_pub, true);

    switch_to_bob_db();
    NewRatchet bob(bob_receiving_bundle->get_shared_secret(), alice_eph_pub, false);

    // alice sends a few
    auto [alice_key1, header1] = alice.advance_send();
    auto [alice_key2, header2] = alice.advance_send();

    ASSERT_EQ(std::get<0>(alice.get_chain_lengths()), 2);
    ASSERT_EQ(std::get<1>(alice.get_chain_lengths()), 0);

    bob.advance_receive(header1);
    bob.advance_receive(header2);

    ASSERT_EQ(std::get<0>(bob.get_chain_lengths()), 0);
    ASSERT_EQ(std::get<1>(bob.get_chain_lengths()), 2);

    auto [bob_key3, header3] = bob.advance_send();

    ASSERT_EQ(std::get<0>(bob.get_chain_lengths()), 1);
    ASSERT_EQ(std::get<1>(bob.get_chain_lengths()), 2);

    alice.advance_receive(header3);

    ASSERT_EQ(std::get<0>(alice.get_chain_lengths()), 0);
    ASSERT_EQ(std::get<1>(alice.get_chain_lengths()), 1);
}

TEST_F(DoubleRatchetTest, OneMessageFromEitherSideTest) {
    //
}

TEST_F(DoubleRatchetTest, MultipleMessageFromOneSideThenMultipleSwitchTest) {
    ///
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
