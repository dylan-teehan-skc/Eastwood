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

TEST_F(DoubleRatchetTest, SharedSecretDerivationTest) {
    switch_to_alice_db();
    unsigned char* shared_secret_alice = alice_sending_bundle->get_shared_secret();

    switch_to_bob_db();
    unsigned char* shared_secret_bob = bob_receiving_bundle->get_shared_secret();

    // Compare the actual values of the shared secrets
    EXPECT_EQ(memcmp(shared_secret_alice, shared_secret_bob, crypto_scalarmult_BYTES), 0);
}

TEST_F(DoubleRatchetTest, SharedSecretDerivationTestNoOnetime) {
    // Create a copy of alice_eph_priv and put it in a shared pointer
    auto alice_eph_priv_copy = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
    memcpy(alice_eph_priv_copy->data(), alice_eph_priv->data(), crypto_sign_SECRETKEYBYTES);

    std::shared_ptr<SecureMemoryBuffer> shared_alice_eph_priv = std::shared_ptr<SecureMemoryBuffer>(alice_eph_priv_copy.release());
    auto alice_sending_bundle_no_onetime = new SendingKeyBundle(
            alice_device_pub,
            alice_eph_pub,
            std::move(shared_alice_eph_priv),
            bob_device_pub,
            bob_presign_pub,
            nullptr,
            bob_presign_signature
        );

    auto bob_receiving_bundle_no_onetime = new ReceivingKeyBundle(
        alice_device_pub,
        alice_eph_pub,
        bob_device_pub,
        nullptr
    );

    switch_to_alice_db();
    unsigned char* shared_secret_alice = alice_sending_bundle_no_onetime->get_shared_secret();

    switch_to_bob_db();
    unsigned char* shared_secret_bob = bob_receiving_bundle_no_onetime->get_shared_secret();

    // Compare the actual values of the shared secrets
    EXPECT_EQ(memcmp(shared_secret_alice, shared_secret_bob, crypto_scalarmult_BYTES), 0);

    delete[] shared_secret_alice;
    delete[] shared_secret_bob;
    delete alice_sending_bundle_no_onetime;
    delete bob_receiving_bundle_no_onetime;
}

TEST_F(DoubleRatchetTest, RatchetBothSidesTest) {
    // Initialize both parties
    switch_to_alice_db();
    auto ratchet_id = new unsigned char[32];
    randombytes_buf(ratchet_id, 32);
    auto alice = alice_sending_bundle->create_ratchet();

    switch_to_bob_db();
    auto bob = bob_receiving_bundle->create_ratchet();

    // Alice sends first message
    switch_to_alice_db();
    auto [alice_key1, header1] = alice->advance_send();
    switch_to_bob_db();
    auto bob_key1 = bob->advance_receive(header1);
    ASSERT_EQ(memcmp(alice_key1.data(), bob_key1, 32), 0);

    // Bob responds
    auto [bob_key2, header2] = bob->advance_send();
    switch_to_alice_db();
    auto alice_key2 = alice->advance_receive(header2);
    ASSERT_EQ(memcmp(bob_key2.data(), alice_key2, 32), 0);

    // Alice sends again (should trigger DH ratchet)
    auto [alice_key3, header3] = alice->advance_send();
    switch_to_bob_db();
    auto bob_key3 = bob->advance_receive(header3);
    ASSERT_EQ(memcmp(alice_key3.data(), bob_key3, 32), 0);
    delete[] ratchet_id;
}

TEST_F(DoubleRatchetTest, TwoMessageFromOneSideTest) {
    // Initialize both parties
    switch_to_alice_db();

    auto ratchet_id = new unsigned char[32];
    randombytes_buf(ratchet_id, 32);
    auto alice = alice_sending_bundle->create_ratchet();

    switch_to_bob_db();
    auto bob = bob_receiving_bundle->create_ratchet();

    // Alice sends first message
    switch_to_alice_db();
    auto [alice_key1, header1] = alice->advance_send();
    auto [alice_key2, header2] = alice->advance_send();
    auto [alice_key3, header3] = alice->advance_send();

    ASSERT_EQ(header1->message_index, 0);
    ASSERT_EQ(header2->message_index, 1);
    ASSERT_EQ(header3->message_index, 2);

    switch_to_bob_db();
    auto bob_key1 = bob->advance_receive(header1);
    auto bob_key2 = bob->advance_receive(header2);
    auto bob_key3 = bob->advance_receive(header3);

    //keys are the same
    ASSERT_EQ(memcmp(alice_key1.data(), bob_key1, 32), 0);
    ASSERT_EQ(memcmp(alice_key2.data(), bob_key2, 32), 0);
    ASSERT_EQ(memcmp(alice_key3.data(), bob_key3, 32), 0);
    delete[] ratchet_id;
}

TEST_F(DoubleRatchetTest, MessageIndexResetTest) {
    // Initialize both parties
    switch_to_alice_db();
    auto ratchet_id = std::make_unique<unsigned char[]>(32);
    randombytes_buf(ratchet_id.get(), 32);
    auto alice = alice_sending_bundle->create_ratchet();

    switch_to_bob_db();
    auto bob = bob_receiving_bundle->create_ratchet();

    // alice sends a few
    auto [alice_key1, header1] = alice->advance_send();
    auto header1_ptr = std::unique_ptr<MessageHeader>(header1);
    
    auto [alice_key2, header2] = alice->advance_send();
    auto header2_ptr = std::unique_ptr<MessageHeader>(header2);

    ASSERT_EQ(std::get<0>(alice->get_chain_lengths()), 2);
    ASSERT_EQ(std::get<1>(alice->get_chain_lengths()), 0);

    auto bob_key1 = std::unique_ptr<unsigned char[]>(bob->advance_receive(header1_ptr.get()));
    auto bob_key2 = std::unique_ptr<unsigned char[]>(bob->advance_receive(header2_ptr.get()));

    ASSERT_EQ(std::get<0>(bob->get_chain_lengths()), 0);
    ASSERT_EQ(std::get<1>(bob->get_chain_lengths()), 2);

    auto [bob_key3, header3] = bob->advance_send();
    auto header3_ptr = std::unique_ptr<MessageHeader>(header3);

    ASSERT_EQ(std::get<0>(bob->get_chain_lengths()), 1);
    ASSERT_EQ(std::get<1>(bob->get_chain_lengths()), 2);

    auto alice_key3 = std::unique_ptr<unsigned char[]>(alice->advance_receive(header3_ptr.get()));

    ASSERT_EQ(std::get<0>(alice->get_chain_lengths()), 2);
    ASSERT_EQ(std::get<1>(alice->get_chain_lengths()), 1);
}

TEST_F(DoubleRatchetTest, OneMessageFromEitherSideTest) {
    // Initialize both parties
    switch_to_alice_db();
    auto ratchet_id = std::make_unique<unsigned char[]>(32);
    randombytes_buf(ratchet_id.get(), 32);
    auto alice = alice_sending_bundle->create_ratchet();

    switch_to_bob_db();
    auto bob = bob_receiving_bundle->create_ratchet();

    auto [alice_key1, header1] = alice->advance_send();
    auto header1_ptr = std::unique_ptr<MessageHeader>(header1);

    auto bob_key1 = std::unique_ptr<unsigned char[]>(bob->advance_receive(header1_ptr.get()));
    ASSERT_EQ(memcmp(alice_key1.data(), bob_key1.get(), 32), 0);

    auto [bob_key2, header2] = bob->advance_send();
    auto header2_ptr = std::unique_ptr<MessageHeader>(header2);

    auto alice_key2 = std::unique_ptr<unsigned char[]>(alice->advance_receive(header2_ptr.get()));
    ASSERT_EQ(memcmp(alice_key2.get(), bob_key2.data(), 32), 0);
}

TEST_F(DoubleRatchetTest, MultipleMessageFromOneSideThenMultipleSwitchTest) {
    // Initialize both parties
    switch_to_alice_db();
    auto ratchet_id = std::make_unique<unsigned char[]>(32);
    randombytes_buf(ratchet_id.get(), 32);
    auto alice = alice_sending_bundle->create_ratchet();

    switch_to_bob_db();
    auto bob = bob_receiving_bundle->create_ratchet();

    // alice sends a few
    auto [alice_key1, header1] = alice->advance_send();
    auto header1_ptr = std::unique_ptr<MessageHeader>(header1);
    
    auto [alice_key2, header2] = alice->advance_send();
    auto header2_ptr = std::unique_ptr<MessageHeader>(header2);

    // bob receives a few
    auto bob_key1 = std::unique_ptr<unsigned char[]>(bob->advance_receive(header1_ptr.get()));
    auto bob_key2 = std::unique_ptr<unsigned char[]>(bob->advance_receive(header2_ptr.get()));

    ASSERT_EQ(memcmp(alice_key1.data(), bob_key1.get(), 32), 0);
    ASSERT_EQ(memcmp(alice_key2.data(), bob_key2.get(), 32), 0);

    // bob sends a few
    auto [bob_key3, header3] = bob->advance_send();
    auto header3_ptr = std::unique_ptr<MessageHeader>(header3);
    
    auto [bob_key4, header4] = bob->advance_send();
    auto header4_ptr = std::unique_ptr<MessageHeader>(header4);

    auto alice_key3 = std::unique_ptr<unsigned char[]>(alice->advance_receive(header3_ptr.get()));
    auto alice_key4 = std::unique_ptr<unsigned char[]>(alice->advance_receive(header4_ptr.get()));

    ASSERT_EQ(memcmp(bob_key3.data(), alice_key3.get(), 32), 0);
    ASSERT_EQ(memcmp(alice_key4.get(), bob_key4.data(), 32), 0);
}

TEST_F(DoubleRatchetTest, OutOfOrderMessageTest) {
    // Initialize both parties
    switch_to_alice_db();
    auto ratchet_id = std::make_unique<unsigned char[]>(32);
    randombytes_buf(ratchet_id.get(), 32);
    auto alice = alice_sending_bundle->create_ratchet();

    switch_to_bob_db();
    auto bob = bob_receiving_bundle->create_ratchet();

    // alice sends a few
    auto [alice_key1, header1] = alice->advance_send();
    auto header1_ptr = std::unique_ptr<MessageHeader>(header1);
    
    auto [alice_key2, header2] = alice->advance_send();
    auto header2_ptr = std::unique_ptr<MessageHeader>(header2);
    
    auto [alice_key3, header3] = alice->advance_send();
    auto header3_ptr = std::unique_ptr<MessageHeader>(header3);

    // bob receives a few
    auto bob_key3 = std::unique_ptr<unsigned char[]>(bob->advance_receive(header3_ptr.get()));
    auto bob_key2 = std::unique_ptr<unsigned char[]>(bob->advance_receive(header2_ptr.get()));
    auto bob_key1 = std::unique_ptr<unsigned char[]>(bob->advance_receive(header1_ptr.get()));

    ASSERT_EQ(memcmp(alice_key1.data(), bob_key1.get(), 32), 0);
    ASSERT_EQ(memcmp(alice_key2.data(), bob_key2.get(), 32), 0);
    ASSERT_EQ(memcmp(alice_key3.data(), bob_key3.get(), 32), 0);
}

TEST_F(DoubleRatchetTest, SkippedMessagesAcrossRatchetTest) {
    switch_to_alice_db();
    auto ratchet_id = std::make_unique<unsigned char[]>(32);
    randombytes_buf(ratchet_id.get(), 32);
    auto alice = alice_sending_bundle->create_ratchet();

    switch_to_bob_db();
    auto bob = bob_receiving_bundle->create_ratchet();

    // alice sends two messages
    auto [alice_key1, header1] = alice->advance_send();
    auto header1_ptr = std::unique_ptr<MessageHeader>(header1);
    
    auto [alice_key2, header2] = alice->advance_send();
    auto header2_ptr = std::unique_ptr<MessageHeader>(header2);

    // bob receives only the second message, skipping first
    auto bob_key2 = std::unique_ptr<unsigned char[]>(bob->advance_receive(header2_ptr.get()));
    ASSERT_EQ(memcmp(alice_key2.data(), bob_key2.get(), 32), 0);

    // alice dh ratchet
    auto [alice_key3, header3] = alice->advance_send();
    auto header3_ptr = std::unique_ptr<MessageHeader>(header3);

    // bob receives the new ratcheted message
    auto bob_key3 = std::unique_ptr<unsigned char[]>(bob->advance_receive(header3_ptr.get()));
    ASSERT_EQ(memcmp(alice_key3.data(), bob_key3.get(), 32), 0);

    // bob receives previous ratchet message
    auto bob_key1 = std::unique_ptr<unsigned char[]>(bob->advance_receive(header1_ptr.get()));
    ASSERT_EQ(memcmp(alice_key1.data(), bob_key1.get(), 32), 0);
}

TEST_F(DoubleRatchetTest, SavingAndLoadingFromDB) {
    // Create initial ratchet
    switch_to_alice_db();
    std::array<unsigned char, 32> device_id;
    randombytes_buf(device_id.data(), 32);
    auto ratchet1 = alice_sending_bundle->create_ratchet();

    ratchet1->save("alice", device_id);
    auto decrypted_ratchet = get_decrypted_ratchet_by_username_device("alice", device_id);
    auto ratchet2 = NewRatchet(decrypted_ratchet);

    EXPECT_EQ(0, memcmp(ratchet1->local_dh_priv->data(), ratchet2.local_dh_priv->data(), 32));
    EXPECT_EQ(0, memcmp(ratchet1->local_dh_public, ratchet2.local_dh_public, 32));
    EXPECT_EQ(0, memcmp(ratchet1->root_key, ratchet2.root_key, 32));
    EXPECT_EQ(0, memcmp(ratchet1->send_chain.key, ratchet2.send_chain.key, 32));
    EXPECT_EQ(ratchet1->send_chain.index, ratchet2.send_chain.index);
    EXPECT_EQ(0, memcmp(ratchet1->receive_chain.key, ratchet2.receive_chain.key, 32));
    EXPECT_EQ(ratchet1->receive_chain.index, ratchet2.receive_chain.index);
}
