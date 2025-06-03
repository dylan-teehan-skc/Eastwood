//
// Created by Josh Sloggett on 31/05/2025.
//

#include <gtest/gtest.h>
#include <tuple>
#include <iostream>
#include <thread>

#include "kek_manager.h"
#include "NewRatchet.h"
#include "utils.h"
#include "database/schema.h"
#include "keys/secure_memory_buffer.h"
#include "algorithms/algorithms.h"
#include "database/database.h"
#include "sessions/KeyBundle.h"
#include "sessions/RatchetSessionManager.h"
#include "key_exchange/MessageStructs.h"

class RatchetSessionManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (sodium_init() < 0) {
            throw std::runtime_error("Libsodium initialization failed");
        }

        // Add small delay to prevent timing issues in CI
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        auto kek = SecureMemoryBuffer::create(SYM_KEY_LEN);
        crypto_secretbox_keygen(kek->data());

        KekManager::instance().setKEK(std::move(kek));

        bool encrypted = false;

        const auto master_key = SecureMemoryBuffer::create(MASTER_KEY_LEN);
        randombytes_buf(master_key->data(), MASTER_KEY_LEN);
        Database::get().initialize("username", master_key, encrypted);

        drop_all_tables();
        init_schema();

        // Initialize all arrays to zero first
        memset(alice_device_pub, 0, sizeof(alice_device_pub));
        memset(alice_to_bob_eph_pub, 0, sizeof(alice_to_bob_eph_pub));
        memset(alice_to_charlie_eph_pub, 0, sizeof(alice_to_charlie_eph_pub));
        memset(bob_device_pub, 0, sizeof(bob_device_pub));
        memset(bob_presign_pub, 0, sizeof(bob_presign_pub));
        memset(bob_onetime_pub, 0, sizeof(bob_onetime_pub));
        memset(bob_presign_signature, 0, sizeof(bob_presign_signature));
        memset(charlie_device_pub, 0, sizeof(charlie_device_pub));
        memset(charlie_eph_pub, 0, sizeof(charlie_eph_pub));
        memset(charlie_presign_pub, 0, sizeof(charlie_presign_pub));
        memset(charlie_onetime_pub, 0, sizeof(charlie_onetime_pub));
        memset(charlie_presign_signature, 0, sizeof(charlie_presign_signature));

        // Initialize SecureMemoryBuffer objects with correct sizes for all users
        // Alice's keys
        alice_device_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        alice_to_bob_eph_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        alice_to_charlie_eph_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        
        // Bob's keys
        bob_device_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        bob_presign_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        bob_onetime_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        
        // Charlie's keys
        charlie_device_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        charlie_eph_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        charlie_presign_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        charlie_onetime_priv = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);

        // Generate keypairs for all users
        // Alice's keypairs
        crypto_sign_keypair(alice_device_pub, alice_device_priv->data());
        crypto_box_keypair(alice_to_bob_eph_pub, alice_to_bob_eph_priv->data());
        crypto_box_keypair(alice_to_charlie_eph_pub, alice_to_charlie_eph_priv->data());

        // Bob's keypairs
        crypto_sign_keypair(bob_device_pub, bob_device_priv->data());
        crypto_box_keypair(bob_presign_pub, bob_presign_priv->data());
        crypto_box_keypair(bob_onetime_pub, bob_onetime_priv->data());

        // Charlie's keypairs
        crypto_sign_keypair(charlie_device_pub, charlie_device_priv->data());
        crypto_box_keypair(charlie_eph_pub, charlie_eph_priv->data());
        crypto_box_keypair(charlie_presign_pub, charlie_presign_priv->data());
        crypto_box_keypair(charlie_onetime_pub, charlie_onetime_priv->data());

        // Generate signatures
        crypto_sign_detached(bob_presign_signature,
            nullptr,
            bob_presign_pub,
            crypto_box_PUBLICKEYBYTES,
            bob_device_priv->data()
        );

        crypto_sign_detached(charlie_presign_signature,
            nullptr,
            charlie_presign_pub,
            crypto_box_PUBLICKEYBYTES,
            charlie_device_priv->data()
        );

        // Create shared pointers for ephemeral private keys
        auto alice_to_bob_eph_priv_copy = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        memcpy(alice_to_bob_eph_priv_copy->data(), alice_to_bob_eph_priv->data(), crypto_sign_SECRETKEYBYTES);
        std::shared_ptr<SecureMemoryBuffer> shared_alice_to_bob_eph_priv = std::shared_ptr<SecureMemoryBuffer>(std::move(alice_to_bob_eph_priv_copy));

        auto alice_to_charlie_eph_priv_copy = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        memcpy(alice_to_charlie_eph_priv_copy->data(), alice_to_charlie_eph_priv->data(), crypto_sign_SECRETKEYBYTES);
        std::shared_ptr<SecureMemoryBuffer> shared_alice_to_charlie_eph_priv = std::shared_ptr<SecureMemoryBuffer>(std::move(alice_to_charlie_eph_priv_copy));

        auto charlie_eph_priv_copy = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        memcpy(charlie_eph_priv_copy->data(), charlie_eph_priv->data(), crypto_sign_SECRETKEYBYTES);
        std::shared_ptr<SecureMemoryBuffer> shared_charlie_eph_priv = std::shared_ptr<SecureMemoryBuffer>(std::move(charlie_eph_priv_copy));

        // Create key bundles for Alice -> Bob
        alice_to_bob_bundle = new SendingKeyBundle(
            alice_device_pub,
            alice_to_bob_eph_pub,
            std::move(shared_alice_to_bob_eph_priv),
            bob_device_pub,
            bob_presign_pub,
            bob_onetime_pub,
            bob_presign_signature
        );

        bob_from_alice_bundle = new ReceivingKeyBundle(
            alice_device_pub,
            alice_to_bob_eph_pub,
            bob_device_pub,
            bob_onetime_pub
        );

        // Create key bundles for Alice -> Charlie
        alice_to_charlie_bundle = new SendingKeyBundle(
            alice_device_pub,
            alice_to_charlie_eph_pub,
            std::move(shared_alice_to_charlie_eph_priv),
            charlie_device_pub,
            charlie_presign_pub,
            charlie_onetime_pub,
            charlie_presign_signature
        );

        charlie_from_alice_bundle = new ReceivingKeyBundle(
            alice_device_pub,
            alice_to_charlie_eph_pub,
            charlie_device_pub,
            charlie_onetime_pub
        );

        // Create key bundles for Bob -> Charlie
        bob_to_charlie_bundle = new SendingKeyBundle(
            bob_device_pub,
            bob_presign_pub,
            std::move(shared_charlie_eph_priv),
            charlie_device_pub,
            charlie_presign_pub,
            charlie_onetime_pub,
            charlie_presign_signature
        );

        charlie_from_bob_bundle = new ReceivingKeyBundle(
            bob_device_pub,
            bob_presign_pub,
            charlie_device_pub,
            charlie_onetime_pub
        );

        // Initialize RatchetSessionManager
        session_manager = std::make_unique<RatchetSessionManager>();
    }

    void TearDown() override {
        // Clean up session manager first to ensure database is not in use
        session_manager.reset();
        
        // Add small delay to ensure all operations are complete
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        
        // Clean up all key bundles
        if (alice_to_bob_bundle) {
            delete alice_to_bob_bundle;
            alice_to_bob_bundle = nullptr;
        }
        if (bob_from_alice_bundle) {
            delete bob_from_alice_bundle;
            bob_from_alice_bundle = nullptr;
        }
        if (alice_to_charlie_bundle) {
            delete alice_to_charlie_bundle;
            alice_to_charlie_bundle = nullptr;
        }
        if (charlie_from_alice_bundle) {
            delete charlie_from_alice_bundle;

            charlie_from_alice_bundle = nullptr;
        }
        if (bob_to_charlie_bundle) {
            delete bob_to_charlie_bundle;
            bob_to_charlie_bundle = nullptr;
        }
        if (charlie_from_bob_bundle) {
            delete charlie_from_bob_bundle;
            charlie_from_bob_bundle = nullptr;
        }

        // Reset database state with proper synchronization
        try {
            drop_all_tables();
        } catch (...) {
            // Ignore errors during cleanup in case database is already closed
        }
        
        // Add final delay to ensure cleanup is complete
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Helper function to create a MessageHeader for testing
    MessageHeader* create_test_header(const unsigned char* dh_public, const unsigned char* device_id, int message_index, int prev_chain_length) {
        auto header = new MessageHeader();
        memcpy(header->dh_public.data(), dh_public, crypto_kx_PUBLICKEYBYTES);
        memcpy(header->device_id.data(), device_id, crypto_box_PUBLICKEYBYTES);
        header->message_index = message_index;
        header->prev_chain_length = prev_chain_length;
        strcpy(header->file_uuid, "test_file_uuid");
        return header;
    }

    void switch_to_alice_db() {
        drop_all_tables();
        init_schema();

        auto nonce = new unsigned char[CHA_CHA_NONCE_LEN];
        randombytes_buf(nonce, CHA_CHA_NONCE_LEN);

        // Create a copy of the private key before moving it
        auto alice_device_priv_copy = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        memcpy(alice_device_priv_copy->data(), alice_device_priv->data(), crypto_sign_SECRETKEYBYTES);

        std::unique_ptr<SecureMemoryBuffer> encrypted_alice_device_priv = encrypt_secret_key(std::move(alice_device_priv_copy), nonce);
        save_encrypted_keypair("device", alice_device_pub, encrypted_alice_device_priv, nonce);

        delete[] nonce;
    }

    void switch_to_bob_db() {
        drop_all_tables();
        init_schema();

        auto nonce = new unsigned char[CHA_CHA_NONCE_LEN];
        randombytes_buf(nonce, CHA_CHA_NONCE_LEN);

        // Create copies of the private keys before moving them
        auto bob_device_priv_copy = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        memcpy(bob_device_priv_copy->data(), bob_device_priv->data(), crypto_sign_SECRETKEYBYTES);
        
        std::unique_ptr<SecureMemoryBuffer> encrypted_bob_device_priv = encrypt_secret_key(std::move(bob_device_priv_copy), nonce);
        save_encrypted_keypair("device", bob_device_pub, encrypted_bob_device_priv, nonce);

        auto nonce_2 = new unsigned char[CHA_CHA_NONCE_LEN];
        randombytes_buf(nonce_2, CHA_CHA_NONCE_LEN);

        auto bob_presign_priv_copy = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        memcpy(bob_presign_priv_copy->data(), bob_presign_priv->data(), crypto_sign_SECRETKEYBYTES);
        
        std::unique_ptr<SecureMemoryBuffer> encrypted_bob_presign_priv = encrypt_secret_key(std::move(bob_presign_priv_copy), nonce_2);
        save_encrypted_keypair("signed", bob_presign_pub, encrypted_bob_presign_priv, nonce_2);

        auto nonce_3 = new unsigned char[CHA_CHA_NONCE_LEN];
        randombytes_buf(nonce_3, CHA_CHA_NONCE_LEN);

        auto bob_onetime_priv_copy = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        memcpy(bob_onetime_priv_copy->data(), bob_onetime_priv->data(), crypto_sign_SECRETKEYBYTES);
        
        std::unique_ptr<SecureMemoryBuffer> encrypted_bob_onetime_priv = encrypt_secret_key(std::move(bob_onetime_priv_copy), nonce_3);

        unsigned char* onetime_pub_copy = new unsigned char[crypto_box_PUBLICKEYBYTES];
        memcpy(onetime_pub_copy, bob_onetime_pub, crypto_box_PUBLICKEYBYTES);

        std::vector<std::tuple<unsigned char*, std::unique_ptr<SecureMemoryBuffer>, unsigned char*>> onetime_keys;
        onetime_keys.emplace_back(onetime_pub_copy, std::move(encrypted_bob_onetime_priv), nonce_3);

        save_encrypted_onetime_keys(std::move(onetime_keys));

        // Clean up all allocated memory
        delete[] onetime_pub_copy;
        delete[] nonce;
        delete[] nonce_2;
        delete[] nonce_3;
    }

    // Helper to print key for debugging
    void print_key(const std::string& label, const unsigned char* key) {
        std::cout << label << ": ";
        for (int i = 0; i < 32; i++) {
            printf("%02x", key[i]);
        }
        std::cout << std::endl;
    }

    // Helper to print key for debugging (std::array version)
    void print_key(const std::string& label, const std::array<unsigned char, 32>& key) {
        std::cout << label << ": ";
        for (int i = 0; i < 32; i++) {
            printf("%02x", key[i]);
        }
        std::cout << std::endl;
    }

    // Test data
    std::unique_ptr<RatchetSessionManager> session_manager;

    // Key bundles for Alice -> Bob
    SendingKeyBundle *alice_to_bob_bundle = nullptr;
    ReceivingKeyBundle *bob_from_alice_bundle = nullptr;

    // Key bundles for Alice -> Charlie
    SendingKeyBundle *alice_to_charlie_bundle = nullptr;
    ReceivingKeyBundle *charlie_from_alice_bundle = nullptr;

    // Key bundles for Bob -> Charlie
    SendingKeyBundle *bob_to_charlie_bundle = nullptr;
    ReceivingKeyBundle *charlie_from_bob_bundle = nullptr;

    // Alice's keys
    unsigned char alice_device_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> alice_device_priv;
    unsigned char alice_to_bob_eph_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> alice_to_bob_eph_priv;
    unsigned char alice_to_charlie_eph_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> alice_to_charlie_eph_priv;

    // Bob's keys
    unsigned char bob_device_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> bob_device_priv;
    unsigned char bob_presign_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> bob_presign_priv;
    unsigned char bob_onetime_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> bob_onetime_priv;
    unsigned char bob_presign_signature[crypto_sign_BYTES] = {};

    // Charlie's keys
    unsigned char charlie_device_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> charlie_device_priv;
    unsigned char charlie_eph_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> charlie_eph_priv;
    unsigned char charlie_presign_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> charlie_presign_priv;
    unsigned char charlie_onetime_pub[crypto_box_PUBLICKEYBYTES] = {};
    std::unique_ptr<SecureMemoryBuffer> charlie_onetime_priv;
    unsigned char charlie_presign_signature[crypto_sign_BYTES] = {};
};

TEST_F(RatchetSessionManagerTest, RatchetCreationTest) {
    switch_to_alice_db();
    // Test that ratchets are created when bundles are provided
    std::vector<KeyBundle*> alice_bundles = {alice_to_bob_bundle};
    session_manager->create_ratchets_if_needed("bob", alice_bundles, false);
    
    // Verify ratchet was created by attempting to get keys
    auto keys = session_manager->get_keys_for_identity("bob", false);
    EXPECT_EQ(keys.size(), 1);
    
    // Check that the device ID matches bob's device public key
    std::array<unsigned char, 32> bob_device_id;
    memcpy(bob_device_id.data(), bob_device_pub, 32);
    EXPECT_NE(keys.find(bob_device_id), keys.end());
}

TEST_F(RatchetSessionManagerTest, MultipleDeviceRatchetCreationTest) {
    // Test creating ratchets for multiple devices
    switch_to_alice_db();
    std::vector<KeyBundle*> alice_bundles = {alice_to_charlie_bundle, alice_to_bob_bundle};
    session_manager->create_ratchets_if_needed("twobundles", alice_bundles, false);
    
    auto keys = session_manager->get_keys_for_identity("twobundles", false);
    EXPECT_EQ(keys.size(), 2);
    
    // Check that both Alice and Bob device IDs are present
    std::array<unsigned char, 32> charlie_device_id;
    std::array<unsigned char, 32> bob_device_id;
    memcpy(charlie_device_id.data(), charlie_device_pub, 32);
    memcpy(bob_device_id.data(), bob_device_pub, 32);
    
    EXPECT_NE(keys.find(charlie_device_id), keys.end());
    EXPECT_NE(keys.find(bob_device_id), keys.end());
}

TEST_F(RatchetSessionManagerTest, DuplicateRatchetPreventionTest) {
    // Test that duplicate ratchets are not created
    switch_to_alice_db();
    std::vector<KeyBundle*>alice_bundles = {alice_to_bob_bundle};
    
    // Create ratchet first time
    session_manager->create_ratchets_if_needed("bob", alice_bundles, false);
    auto keys1 = session_manager->get_keys_for_identity("bob", false);
    
    // Attempt to create again - should not create duplicates
    session_manager->create_ratchets_if_needed("bob", alice_bundles, false);
    auto keys2 = session_manager->get_keys_for_identity("bob", false);
    
    EXPECT_EQ(keys1.size(), keys2.size());
    EXPECT_EQ(keys1.size(), 1);
}

TEST_F(RatchetSessionManagerTest, KeyGenerationForSendingTest) {
    // Test that keys are properly generated for sending
    switch_to_alice_db();
    std::vector<KeyBundle*> alice_bundles = {alice_to_bob_bundle};
    session_manager->create_ratchets_if_needed("bob", alice_bundles, false);
    
    auto keys = session_manager->get_keys_for_identity("bob", false);
    EXPECT_EQ(keys.size(), 1);
    
    std::array<unsigned char, 32> bob_device_id;
    memcpy(bob_device_id.data(), bob_device_pub, 32);
    
    auto it = keys.find(bob_device_id);
    ASSERT_NE(it, keys.end());
    
    auto [message_key, header] = it->second;
    
    // Verify header is properly initialized
    EXPECT_NE(header, nullptr);
    EXPECT_EQ(header->message_index, 0); // First message should have index 0
    EXPECT_EQ(header->prev_chain_length, 0);
    
    // Verify message key is not all zeros
    bool all_zeros = true;
    for (int i = 0; i < 32; i++) {
        if (message_key[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros);
    
    // Clean up
    delete header;
}

TEST_F(RatchetSessionManagerTest, KeyGenerationConsistencyTest) {
    // Test that sending and receiving keys match

    // Debug: Show the device IDs we're working with
    std::cout << "=== DEVICE IDS ===" << std::endl;
    std::cout << "Alice device ID: ";
    for (int i = 0; i < 32; i++) {
        printf("%02x", alice_device_pub[i]);
    }
    std::cout << std::endl;
    std::cout << "Bob device ID: ";
    for (int i = 0; i < 32; i++) {
        printf("%02x", bob_device_pub[i]);
    }
    std::cout << std::endl;

    // Alice's perspective (sender)
    switch_to_alice_db();
    auto alice_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> alice_bundles = {alice_to_bob_bundle};
    alice_session_manager->create_ratchets_if_needed("bob", alice_bundles, false);

    // Get sending key from Alice's perspective
    auto alice_keys = alice_session_manager->get_keys_for_identity("bob", false);
    std::array<unsigned char, 32> bob_device_id;
    memcpy(bob_device_id.data(), bob_device_pub, 32);
    auto [alice_message_key, alice_header] = alice_keys[bob_device_id];

    // Debug print Alice's message key and header
    printf("Alice message key: ");
    for (int i = 0; i < 32; ++i) printf("%02x", alice_message_key[i]);
    printf("\nHeader: message_index=%d, dh_public=", alice_header->message_index);
    for (int i = 0; i < 32; ++i) printf("%02x", alice_header->dh_public[i]);
    printf("\n");

    // Bob's perspective (receiver)
    switch_to_bob_db();
    auto bob_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> bob_bundles = {bob_from_alice_bundle};
    bob_session_manager->create_ratchets_if_needed("alice", bob_bundles, false);

    std::cout << "=== RECEIVING MESSAGE ===" << std::endl;
    // Get receiving key from Bob's perspective using Alice's header
    auto bob_message_key = bob_session_manager->get_key_for_device("alice", alice_header);

    // Debug print Bob's message key
    printf("Bob message key: ");
    for (int i = 0; i < 32; ++i) printf("%02x", bob_message_key[i]);
    printf("\n");

    // Keys should match
    printf("Comparing Alice and Bob message keys:\n");
    for (int i = 0; i < 32; ++i) printf("%02x", alice_message_key[i]);
    printf("\n");
    for (int i = 0; i < 32; ++i) printf("%02x", bob_message_key[i]);
    printf("\n");
    EXPECT_EQ(memcmp(alice_message_key.data(), bob_message_key, 32), 0);

    // Clean up
    delete alice_header;
    delete[] bob_message_key;
}

// ===== EXTENSIVE KEY GENERATION CONSISTENCY TESTS =====

TEST_F(RatchetSessionManagerTest, MultipleSequentialSendKeyConsistencyTest) {
    std::cout << "\n=== Multiple Sequential Send Key Consistency Test ===" << std::endl;
    
    // Alice's perspective (sender)
    switch_to_alice_db();
    auto alice_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> alice_bundles = {alice_to_bob_bundle};
    alice_session_manager->create_ratchets_if_needed("bob", alice_bundles, false);

    // Bob's perspective (receiver)
    switch_to_bob_db();
    auto bob_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> bob_bundles = {bob_from_alice_bundle};
    bob_session_manager->create_ratchets_if_needed("alice", bob_bundles, false);

    const int num_messages = 5;
    std::vector<std::array<unsigned char, 32>> alice_keys;
    std::vector<MessageHeader*> headers;

    std::array<unsigned char, 32> bob_device_id;
    memcpy(bob_device_id.data(), bob_device_pub, 32);

    // Alice sends multiple messages
    switch_to_alice_db();
    for (int i = 0; i < num_messages; i++) {
        auto alice_keys_map = alice_session_manager->get_keys_for_identity("bob", false);
        auto [message_key, header] = alice_keys_map[bob_device_id];
        alice_keys.push_back(message_key);
        headers.push_back(header);
        print_key("Alice sends key " + std::to_string(i), message_key);
    }

    // Bob receives all messages in order
    switch_to_bob_db();
    for (int i = 0; i < num_messages; i++) {
        auto bob_key = bob_session_manager->get_key_for_device("alice", headers[i]);
        print_key("Bob receives key " + std::to_string(i), bob_key);
        
        ASSERT_EQ(memcmp(alice_keys[i].data(), bob_key, 32), 0) 
            << "Key mismatch at message " << i;
        
        delete[] bob_key;
        delete headers[i];
    }
}

TEST_F(RatchetSessionManagerTest, AlternatingKeyGenerationConsistencyTest) {
    std::cout << "\n=== Alternating Key Generation Consistency Test ===" << std::endl;
    
    // Setup Alice
    switch_to_alice_db();
    auto alice_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> alice_bundles = {alice_to_bob_bundle};
    alice_session_manager->create_ratchets_if_needed("bob", alice_bundles, false);

    // Setup Bob 
    switch_to_bob_db();
    auto bob_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> bob_bundles = {bob_from_alice_bundle};
    bob_session_manager->create_ratchets_if_needed("alice", bob_bundles, false);

    std::array<unsigned char, 32> bob_device_id;
    memcpy(bob_device_id.data(), bob_device_pub, 32);
    std::array<unsigned char, 32> alice_device_id;
    memcpy(alice_device_id.data(), alice_device_pub, 32);

    const int num_rounds = 3;
    
    for (int round = 0; round < num_rounds; round++) {
        std::cout << "\n--- Round " << round + 1 << " ---" << std::endl;
        
        // Alice sends
        switch_to_alice_db();
        auto alice_keys_map = alice_session_manager->get_keys_for_identity("bob", false);
        auto [alice_key, alice_header] = alice_keys_map[bob_device_id];
        print_key("Alice sends key", alice_key);

        switch_to_bob_db();
        auto bob_received_key = bob_session_manager->get_key_for_device("alice", alice_header);
        print_key("Bob receives Alice's key", bob_received_key);

        ASSERT_EQ(memcmp(alice_key.data(), bob_received_key, 32), 0)
            << "Alice->Bob key mismatch in round " << round + 1;

        // Bob responds
        auto bob_keys_map = bob_session_manager->get_keys_for_identity("alice", false);
        auto [bob_key, bob_header] = bob_keys_map[alice_device_id];
        print_key("Bob sends key", bob_key);

        switch_to_alice_db();
        auto alice_received_key = alice_session_manager->get_key_for_device("bob", bob_header);
        print_key("Alice receives Bob's key", alice_received_key);

        ASSERT_EQ(memcmp(bob_key.data(), alice_received_key, 32), 0)
            << "Bob->Alice key mismatch in round " << round + 1;

        delete alice_header;
        delete bob_header;
        delete[] bob_received_key;
        delete[] alice_received_key;
    }
}

TEST_F(RatchetSessionManagerTest, BurstSendKeyConsistencyTest) {
    std::cout << "\n=== Burst Send Key Consistency Test ===" << std::endl;
    
    // Setup Alice
    switch_to_alice_db();
    auto alice_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> alice_bundles = {alice_to_bob_bundle};
    alice_session_manager->create_ratchets_if_needed("bob", alice_bundles, false);

    // Setup Bob
    switch_to_bob_db();
    auto bob_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> bob_bundles = {bob_from_alice_bundle};
    bob_session_manager->create_ratchets_if_needed("alice", bob_bundles, false);

    std::array<unsigned char, 32> bob_device_id;
    memcpy(bob_device_id.data(), bob_device_pub, 32);
    std::array<unsigned char, 32> alice_device_id;
    memcpy(alice_device_id.data(), alice_device_pub, 32);

    // Alice sends burst of messages
    const int alice_burst_size = 3;
    std::vector<std::array<unsigned char, 32>> alice_keys;
    std::vector<MessageHeader*> alice_headers;

    switch_to_alice_db();
    for (int i = 0; i < alice_burst_size; i++) {
        auto alice_keys_map = alice_session_manager->get_keys_for_identity("bob", false);
        auto [key, header] = alice_keys_map[bob_device_id];
        alice_keys.push_back(key);
        alice_headers.push_back(header);
        print_key("Alice burst key " + std::to_string(i), key);
    }

    // Bob receives all Alice's messages
    switch_to_bob_db();
    for (int i = 0; i < alice_burst_size; i++) {
        auto bob_key = bob_session_manager->get_key_for_device("alice", alice_headers[i]);
        print_key("Bob receives Alice burst key " + std::to_string(i), bob_key);
        
        ASSERT_EQ(memcmp(alice_keys[i].data(), bob_key, 32), 0)
            << "Alice burst key mismatch at index " << i;
        
        delete[] bob_key;
    }

    // Bob responds with his own burst
    const int bob_burst_size = 4;
    std::vector<std::array<unsigned char, 32>> bob_keys;
    std::vector<MessageHeader*> bob_headers;

    for (int i = 0; i < bob_burst_size; i++) {
        auto bob_keys_map = bob_session_manager->get_keys_for_identity("alice", false);
        auto [key, header] = bob_keys_map[alice_device_id];
        bob_keys.push_back(key);
        bob_headers.push_back(header);
        print_key("Bob burst key " + std::to_string(i), key);
    }

    // Alice receives all Bob's messages
    switch_to_alice_db();
    for (int i = 0; i < bob_burst_size; i++) {
        auto alice_key = alice_session_manager->get_key_for_device("bob", bob_headers[i]);
        print_key("Alice receives Bob burst key " + std::to_string(i), alice_key);
        
        ASSERT_EQ(memcmp(bob_keys[i].data(), alice_key, 32), 0)
            << "Bob burst key mismatch at index " << i;
        
        delete[] alice_key;
    }

    // Clean up
    for (auto header : alice_headers) delete header;
    for (auto header : bob_headers) delete header;
}

TEST_F(RatchetSessionManagerTest, KeyUniquenessTest) {
    std::cout << "\n=== Key Uniqueness Test ===" << std::endl;
    
    // Setup Alice
    switch_to_alice_db();
    auto alice_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> alice_bundles = {alice_to_bob_bundle};
    alice_session_manager->create_ratchets_if_needed("bob", alice_bundles, false);

    // Setup Bob
    switch_to_bob_db();
    auto bob_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> bob_bundles = {bob_from_alice_bundle};
    bob_session_manager->create_ratchets_if_needed("alice", bob_bundles, false);

    std::array<unsigned char, 32> bob_device_id;
    memcpy(bob_device_id.data(), bob_device_pub, 32);
    std::array<unsigned char, 32> alice_device_id;
    memcpy(alice_device_id.data(), alice_device_pub, 32);

    const int num_keys = 20;
    std::vector<std::array<unsigned char, 32>> all_keys;

    // Generate keys from alternating sends
    for (int i = 0; i < num_keys / 2; i++) {
        // Alice sends
        switch_to_alice_db();
        auto alice_keys_map = alice_session_manager->get_keys_for_identity("bob", false);
        auto [alice_key, alice_header] = alice_keys_map[bob_device_id];
        all_keys.push_back(alice_key);

        // Bob receives and responds
        switch_to_bob_db();
        auto bob_received_key = bob_session_manager->get_key_for_device("alice", alice_header);
        auto bob_keys_map = bob_session_manager->get_keys_for_identity("alice", false);
        auto [bob_key, bob_header] = bob_keys_map[alice_device_id];
        all_keys.push_back(bob_key);

        // Alice receives Bob's response
        switch_to_alice_db();
        auto alice_received_key = alice_session_manager->get_key_for_device("bob", bob_header);

        delete alice_header;
        delete bob_header;
        delete[] bob_received_key;
        delete[] alice_received_key;
    }

    // Verify all keys are unique
    std::cout << "Checking uniqueness of " << all_keys.size() << " keys..." << std::endl;
    for (size_t i = 0; i < all_keys.size(); i++) {
        for (size_t j = i + 1; j < all_keys.size(); j++) {
            ASSERT_NE(memcmp(all_keys[i].data(), all_keys[j].data(), 32), 0)
                << "Duplicate keys found at indices " << i << " and " << j;
        }
    }
    
    std::cout << "All " << all_keys.size() << " keys are unique!" << std::endl;
}

TEST_F(RatchetSessionManagerTest, CrossRatchetKeyConsistencyTest) {
    std::cout << "\n=== Cross Ratchet Key Consistency Test ===" << std::endl;
    
    // Setup Alice
    switch_to_alice_db();
    auto alice_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> alice_bundles = {alice_to_bob_bundle};
    alice_session_manager->create_ratchets_if_needed("bob", alice_bundles, false);

    // Setup Bob
    switch_to_bob_db();
    auto bob_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> bob_bundles = {bob_from_alice_bundle};
    bob_session_manager->create_ratchets_if_needed("alice", bob_bundles, false);

    std::array<unsigned char, 32> bob_device_id;
    memcpy(bob_device_id.data(), bob_device_pub, 32);
    std::array<unsigned char, 32> alice_device_id;
    memcpy(alice_device_id.data(), alice_device_pub, 32);

    // Test pattern: Alice sends, Bob responds, Alice sends more (triggers DH ratchet)
    
    // Alice sends initial message
    switch_to_alice_db();
    auto alice_keys_map1 = alice_session_manager->get_keys_for_identity("bob", false);
    auto [alice_key1, alice_header1] = alice_keys_map1[bob_device_id];
    print_key("Alice sends key 1", alice_key1);

    switch_to_bob_db();
    auto bob_received_key1 = bob_session_manager->get_key_for_device("alice", alice_header1);
    print_key("Bob receives Alice's key 1", bob_received_key1);
    ASSERT_EQ(memcmp(alice_key1.data(), bob_received_key1, 32), 0);

    // Bob responds (this should trigger DH ratchet)
    auto bob_keys_map1 = bob_session_manager->get_keys_for_identity("alice", false);
    auto [bob_key1, bob_header1] = bob_keys_map1[alice_device_id];
    print_key("Bob sends key 1", bob_key1);

    switch_to_alice_db();
    auto alice_received_key1 = alice_session_manager->get_key_for_device("bob", bob_header1);
    print_key("Alice receives Bob's key 1", alice_received_key1);
    ASSERT_EQ(memcmp(bob_key1.data(), alice_received_key1, 32), 0);

    // Alice sends more messages (new DH ratchet should be in effect)
    auto alice_keys_map2 = alice_session_manager->get_keys_for_identity("bob", false);
    auto [alice_key2, alice_header2] = alice_keys_map2[bob_device_id];
    print_key("Alice sends key 2 (new ratchet)", alice_key2);

    switch_to_bob_db();
    auto bob_received_key2 = bob_session_manager->get_key_for_device("alice", alice_header2);
    print_key("Bob receives Alice's key 2 (new ratchet)", bob_received_key2);
    ASSERT_EQ(memcmp(alice_key2.data(), bob_received_key2, 32), 0);

    // Bob sends another message
    auto bob_keys_map2 = bob_session_manager->get_keys_for_identity("alice", false);
    auto [bob_key2, bob_header2] = bob_keys_map2[alice_device_id];
    print_key("Bob sends key 2", bob_key2);

    switch_to_alice_db();
    auto alice_received_key2 = alice_session_manager->get_key_for_device("bob", bob_header2);
    print_key("Alice receives Bob's key 2", alice_received_key2);
    ASSERT_EQ(memcmp(bob_key2.data(), alice_received_key2, 32), 0);

    // Clean up
    delete alice_header1;
    delete bob_header1;
    delete alice_header2;
    delete bob_header2;
    delete[] bob_received_key1;
    delete[] alice_received_key1;
    delete[] bob_received_key2;
    delete[] alice_received_key2;
}

TEST_F(RatchetSessionManagerTest, LongChainKeyConsistencyTest) {
    std::cout << "\n=== Long Chain Key Consistency Test ===" << std::endl;
    
    // Setup Alice
    switch_to_alice_db();
    auto alice_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> alice_bundles = {alice_to_bob_bundle};
    alice_session_manager->create_ratchets_if_needed("bob", alice_bundles, false);

    // Setup Bob
    switch_to_bob_db();
    auto bob_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> bob_bundles = {bob_from_alice_bundle};
    bob_session_manager->create_ratchets_if_needed("alice", bob_bundles, false);

    std::array<unsigned char, 32> bob_device_id;
    memcpy(bob_device_id.data(), bob_device_pub, 32);
    std::array<unsigned char, 32> alice_device_id;
    memcpy(alice_device_id.data(), alice_device_pub, 32);

    const int long_chain_length = 10;
    std::vector<std::array<unsigned char, 32>> alice_keys;
    std::vector<MessageHeader*> headers;

    // Alice sends a long chain of messages
    switch_to_alice_db();
    for (int i = 0; i < long_chain_length; i++) {
        auto alice_keys_map = alice_session_manager->get_keys_for_identity("bob", false);
        auto [key, header] = alice_keys_map[bob_device_id];
        alice_keys.push_back(key);
        headers.push_back(header);
        print_key("Alice long chain key " + std::to_string(i), key);
    }

    // Bob receives all messages in order
    switch_to_bob_db();
    for (int i = 0; i < long_chain_length; i++) {
        auto bob_key = bob_session_manager->get_key_for_device("alice", headers[i]);
        print_key("Bob receives long chain key " + std::to_string(i), bob_key);
        
        ASSERT_EQ(memcmp(alice_keys[i].data(), bob_key, 32), 0)
            << "Long chain key mismatch at index " << i;
        
        delete[] bob_key;
    }

    // Now Bob sends a long chain back
    std::vector<std::array<unsigned char, 32>> bob_keys;
    std::vector<MessageHeader*> bob_headers;

    for (int i = 0; i < long_chain_length; i++) {
        auto bob_keys_map = bob_session_manager->get_keys_for_identity("alice", false);
        auto [key, header] = bob_keys_map[alice_device_id];
        bob_keys.push_back(key);
        bob_headers.push_back(header);
        print_key("Bob long chain key " + std::to_string(i), key);
    }

    // Alice receives all Bob's messages
    switch_to_alice_db();
    for (int i = 0; i < long_chain_length; i++) {
        auto alice_key = alice_session_manager->get_key_for_device("bob", bob_headers[i]);
        print_key("Alice receives Bob's long chain key " + std::to_string(i), alice_key);
        
        ASSERT_EQ(memcmp(bob_keys[i].data(), alice_key, 32), 0)
            << "Long chain key mismatch at index " << i;
        
        delete[] alice_key;
    }

    // Clean up
    for (auto header : headers) delete header;
    for (auto header : bob_headers) delete header;
}

TEST_F(RatchetSessionManagerTest, LoadRatchetsFromDatabaseTest) {
    std::cout << "\n=== Load Ratchets From Database Test ===" << std::endl;
    
    // Phase 1: Create and save ratchets to database
    std::cout << "Phase 1: Creating and saving ratchets..." << std::endl;
    
    // Setup Alice with Bob and Charlie ratchets
    switch_to_alice_db();
    auto alice_session_manager1 = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> alice_bundles = {alice_to_bob_bundle, alice_to_charlie_bundle};
    alice_session_manager1->create_ratchets_if_needed("contacts", alice_bundles);
    
    // Generate some keys to advance ratchet state
    std::array<unsigned char, 32> bob_device_id;
    std::array<unsigned char, 32> charlie_device_id;
    memcpy(bob_device_id.data(), bob_device_pub, 32);
    memcpy(charlie_device_id.data(), charlie_device_pub, 32);
    
    auto alice_keys1 = alice_session_manager1->get_keys_for_identity("contacts", false);
    auto [alice_key_bob1, alice_header_bob1] = alice_keys1[bob_device_id];
    auto [alice_key_charlie1, alice_header_charlie1] = alice_keys1[charlie_device_id];
    
    std::cout << "Generated initial keys and saved ratchets to database" << std::endl;
    print_key("Alice->Bob key 1", alice_key_bob1);
    print_key("Alice->Charlie key 1", alice_key_charlie1);
    
    // Advance ratchets further
    auto alice_keys2 = alice_session_manager1->get_keys_for_identity("contacts", false);
    auto [alice_key_bob2, alice_header_bob2] = alice_keys2[bob_device_id];
    auto [alice_key_charlie2, alice_header_charlie2] = alice_keys2[charlie_device_id];
    
    print_key("Alice->Bob key 2", alice_key_bob2);
    print_key("Alice->Charlie key 2", alice_key_charlie2);
    
    // Destroy the session manager to simulate application restart
    alice_session_manager1.reset();
    
    // Phase 2: Load ratchets from database in fresh session manager
    std::cout << "\nPhase 2: Loading ratchets from database..." << std::endl;
    
    auto alice_session_manager2 = std::make_unique<RatchetSessionManager>();
    alice_session_manager2->load_ratchets_from_db();
    
    // Phase 3: Verify loaded ratchets work correctly
    std::cout << "Phase 3: Verifying loaded ratchets..." << std::endl;
    
    // Generate keys with loaded ratchets - these should continue from where we left off
    auto alice_keys3 = alice_session_manager2->get_keys_for_identity("contacts", false);
    auto [alice_key_bob3, alice_header_bob3] = alice_keys3[bob_device_id];
    auto [alice_key_charlie3, alice_header_charlie3] = alice_keys3[charlie_device_id];
    
    print_key("Alice->Bob key 3 (after reload)", alice_key_bob3);
    print_key("Alice->Charlie key 3 (after reload)", alice_key_charlie3);
    
    // Keys should be different (proving ratchet state was preserved)
    ASSERT_NE(memcmp(alice_key_bob1.data(), alice_key_bob3.data(), 32), 0)
        << "Bob key 3 should be different from key 1";
    ASSERT_NE(memcmp(alice_key_bob2.data(), alice_key_bob3.data(), 32), 0)
        << "Bob key 3 should be different from key 2";
    ASSERT_NE(memcmp(alice_key_charlie1.data(), alice_key_charlie3.data(), 32), 0)
        << "Charlie key 3 should be different from key 1";
    ASSERT_NE(memcmp(alice_key_charlie2.data(), alice_key_charlie3.data(), 32), 0)
        << "Charlie key 3 should be different from key 2";
    
    // Phase 4: Test message exchange with loaded ratchets
    std::cout << "Phase 4: Testing message exchange with loaded ratchets..." << std::endl;
    
    // Setup Bob's session manager and test receiving Alice's messages
    switch_to_bob_db();
    auto bob_session_manager = std::make_unique<RatchetSessionManager>();
    std::vector<KeyBundle*> bob_bundles = {bob_from_alice_bundle};
    bob_session_manager->create_ratchets_if_needed("alice", bob_bundles);
    
    // Bob should be able to receive messages generated by loaded ratchets
    // First, Bob needs to catch up by receiving the earlier messages
    auto bob_received_key1 = bob_session_manager->get_key_for_device("alice", alice_header_bob1);
    auto bob_received_key2 = bob_session_manager->get_key_for_device("alice", alice_header_bob2);
    auto bob_received_key3 = bob_session_manager->get_key_for_device("alice", alice_header_bob3);
    
    print_key("Bob received key 1", bob_received_key1);
    print_key("Bob received key 2", bob_received_key2);
    print_key("Bob received key 3", bob_received_key3);
    
    // Verify the keys match
    ASSERT_EQ(memcmp(alice_key_bob1.data(), bob_received_key1, 32), 0)
        << "Bob should receive correct key 1";
    ASSERT_EQ(memcmp(alice_key_bob2.data(), bob_received_key2, 32), 0)
        << "Bob should receive correct key 2";
    ASSERT_EQ(memcmp(alice_key_bob3.data(), bob_received_key3, 32), 0)
        << "Bob should receive correct key 3 from loaded ratchet";
    
    // Phase 5: Test bidirectional communication with loaded ratchets
    std::cout << "Phase 5: Testing bidirectional communication..." << std::endl;
    
    // Bob responds
    std::array<unsigned char, 32> alice_device_id;
    memcpy(alice_device_id.data(), alice_device_pub, 32);
    
    auto bob_keys = bob_session_manager->get_keys_for_identity("alice", false);
    auto [bob_key, bob_header] = bob_keys[alice_device_id];
    print_key("Bob response key", bob_key);
    
    // Alice receives Bob's response using loaded ratchet
    switch_to_alice_db();
    auto alice_received_key = alice_session_manager2->get_key_for_device("contacts", bob_header);
    print_key("Alice received Bob's response", alice_received_key);
    
    ASSERT_EQ(memcmp(bob_key.data(), alice_received_key, 32), 0)
        << "Alice should receive Bob's response correctly using loaded ratchet";
    
    std::cout << "Successfully verified ratchet persistence and functionality!" << std::endl;
    
    // Clean up
    delete alice_header_bob1;
    delete alice_header_bob2;
    delete alice_header_bob3;
    delete alice_header_charlie1;
    delete alice_header_charlie2;
    delete alice_header_charlie3;
    delete bob_header;
    delete[] bob_received_key1;
    delete[] bob_received_key2;
    delete[] bob_received_key3;
    delete[] alice_received_key;
}

TEST_F(RatchetSessionManagerTest, LoadRatchetsFromEmptyDatabaseTest) {
    std::cout << "\n=== Load Ratchets From Empty Database Test ===" << std::endl;
    
    // Test loading ratchets when database is empty
    switch_to_alice_db();
    auto alice_session_manager = std::make_unique<RatchetSessionManager>();
    
    // This should not throw and should load zero ratchets
    ASSERT_NO_THROW(alice_session_manager->load_ratchets_from_db());
    
    // Verify no ratchets were loaded by checking that get_keys_for_identity returns empty
    auto keys = alice_session_manager->get_keys_for_identity("nonexistent_user", false);
    EXPECT_EQ(keys.size(), 0) << "Should return empty map for non-existent user";
    
    std::cout << "Successfully handled empty database case" << std::endl;
}

