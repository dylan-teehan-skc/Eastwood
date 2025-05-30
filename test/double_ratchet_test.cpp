//
// Created by Josh Sloggett on 30/05/2025.
//

#include <gtest/gtest.h>

#include "kek_manager.h"
#include "NewRatchet.h"
#include "utils.h"
#include "database/schema.h"
#include "src/key_exchange/DoubleRatchet.h"

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

TEST_F(DoubleRatchetTest, FullRatchetTest) {
    // Initialize both parties
    switch_to_alice_db();

    NewRatchet alice(alice_sending_bundle->get_shared_secret(), bob_presign_pub, true);

    switch_to_bob_db();
    NewRatchet bob(bob_receiving_bundle->get_shared_secret(), alice_eph_pub, false);

    // Alice sends first message
    switch_to_alice_db();
    auto alice_key1 = alice.advance_send();
    switch_to_bob_db();
    auto bob_key1 = bob.advance_receive(alice.get_current_dh_public());
    ASSERT_EQ(memcmp(alice_key1, bob_key1, 32), 0);

    // Bob responds
    auto bob_key2 = bob.advance_send();
    switch_to_alice_db();
    auto alice_key2 = alice.advance_receive(bob.get_current_dh_public());
    ASSERT_EQ(memcmp(bob_key2, alice_key2, 32), 0);

    // Alice sends again (should trigger DH ratchet)
    auto alice_key3 = alice.advance_send();
    switch_to_bob_db();
    auto bob_key3 = bob.advance_receive(alice.get_current_dh_public());
    ASSERT_EQ(memcmp(alice_key3, bob_key3, 32), 0);
}

TEST_F(DoubleRatchetTest, TwoMessageFromOneSideTest) {
    // alice ratchet
    switch_to_alice_db();
    std::unique_ptr<DoubleRatchet> alice_ratchet = std::make_unique<DoubleRatchet>(alice_sending_bundle);

    auto plaintext_message = new unsigned char[10];
    randombytes_buf(plaintext_message, 10);
    DeviceMessage* device_message = alice_ratchet.get()->message_send(plaintext_message);

    auto plaintext_message2 = new unsigned char[20];
    randombytes_buf(plaintext_message2, 20);
    DeviceMessage* device_message2 = alice_ratchet.get()->message_send(plaintext_message2);

    //bob ratchet
    switch_to_bob_db();
    std::unique_ptr<DoubleRatchet> bob_ratchet = std::make_unique<DoubleRatchet>(bob_receiving_bundle);

    std::vector<unsigned char> decrypted_message = bob_ratchet.get()->message_receive(*device_message);
    std::vector<unsigned char> decrypted_message2 = bob_ratchet.get()->message_receive(*device_message2);

    EXPECT_EQ(decrypted_message.size(), 10);
    EXPECT_EQ(decrypted_message2.size(), 20);
    EXPECT_EQ(memcmp(decrypted_message.data(), plaintext_message, 10), 0);
    EXPECT_EQ(memcmp(decrypted_message2.data(), plaintext_message2, 20), 0);

    delete[] plaintext_message;
    delete[] plaintext_message2;
    delete device_message;
    delete device_message2;
}

TEST_F(DoubleRatchetTest, OutOfOrderMessagesFromOneSideTest) {
    // alice ratchet
    switch_to_alice_db();
    std::unique_ptr<DoubleRatchet> alice_ratchet = std::make_unique<DoubleRatchet>(alice_sending_bundle);

    auto plaintext_message = new unsigned char[10];
    randombytes_buf(plaintext_message, 10);
    DeviceMessage* device_message = alice_ratchet.get()->message_send(plaintext_message);

    auto plaintext_message2 = new unsigned char[20];
    randombytes_buf(plaintext_message2, 20);
    DeviceMessage* device_message2 = alice_ratchet.get()->message_send(plaintext_message2);

    auto plaintext_message3 = new unsigned char[30];
    randombytes_buf(plaintext_message3, 30);
    DeviceMessage* device_message3 = alice_ratchet.get()->message_send(plaintext_message3);

    //bob ratchet
    switch_to_bob_db();
    std::unique_ptr<DoubleRatchet> bob_ratchet = std::make_unique<DoubleRatchet>(bob_receiving_bundle);

    std::vector<unsigned char> decrypted_message3 = bob_ratchet.get()->message_receive(*device_message3);
    std::vector<unsigned char> decrypted_message2 = bob_ratchet.get()->message_receive(*device_message2);
    std::vector<unsigned char> decrypted_message = bob_ratchet.get()->message_receive(*device_message);

    EXPECT_EQ(decrypted_message.size(), 10);
    EXPECT_EQ(decrypted_message2.size(), 20);
    EXPECT_EQ(decrypted_message3.size(), 30);
    EXPECT_EQ(memcmp(decrypted_message.data(), plaintext_message, 10), 0);
    EXPECT_EQ(memcmp(decrypted_message2.data(), plaintext_message2, 20), 0);
    EXPECT_EQ(memcmp(decrypted_message3.data(), plaintext_message3, 30), 0);

    delete[] plaintext_message;
    delete[] plaintext_message2;
    delete[] plaintext_message3;
    delete device_message;
    delete device_message2;
    delete device_message3;
}

TEST_F(DoubleRatchetTest, OneMessageFromEitherSideTest) {
    // alice ratchet
    switch_to_alice_db();
    std::unique_ptr<DoubleRatchet> alice_ratchet = std::make_unique<DoubleRatchet>(alice_sending_bundle);

    auto plaintext_message = new unsigned char[10];
    randombytes_buf(plaintext_message, 10);
    DeviceMessage* device_message = alice_ratchet.get()->message_send(plaintext_message);

    //bob ratchet
    switch_to_bob_db();
    std::unique_ptr<DoubleRatchet> bob_ratchet = std::make_unique<DoubleRatchet>(bob_receiving_bundle);

    std::vector<unsigned char> decrypted_message = bob_ratchet.get()->message_receive(*device_message);

    EXPECT_EQ(decrypted_message.size(), 10);
    EXPECT_EQ(memcmp(decrypted_message.data(), plaintext_message, 10), 0);

    //now bob sends

    auto plaintext_message2 = new unsigned char[10];
    randombytes_buf(plaintext_message2, 10);
    DeviceMessage* device_message2 = bob_ratchet.get()->message_send(plaintext_message2);

    switch_to_alice_db();
    std::vector<unsigned char> decrypted_message2 = alice_ratchet.get()->message_receive(*device_message2);

    EXPECT_EQ(decrypted_message2.size(), 10);
    EXPECT_EQ(memcmp(decrypted_message2.data(), plaintext_message2, 10), 0);

    delete[] plaintext_message;
    delete[] plaintext_message2;
    delete device_message;
    delete device_message2;
}

TEST_F(DoubleRatchetTest, MultipleMessageFromOneSideThenSwitchTest) {
    // alice ratchet
    switch_to_alice_db();
    std::unique_ptr<DoubleRatchet> alice_ratchet = std::make_unique<DoubleRatchet>(alice_sending_bundle);

    auto plaintext_message = new unsigned char[10];
    randombytes_buf(plaintext_message, 10);
    DeviceMessage* device_message = alice_ratchet.get()->message_send(plaintext_message);

    auto plaintext_message2 = new unsigned char[10];
    randombytes_buf(plaintext_message2, 10);
    DeviceMessage* device_message2 = alice_ratchet.get()->message_send(plaintext_message2);

    //bob ratchet
    switch_to_bob_db();
    std::unique_ptr<DoubleRatchet> bob_ratchet = std::make_unique<DoubleRatchet>(bob_receiving_bundle);

    std::vector<unsigned char> decrypted_message = bob_ratchet.get()->message_receive(*device_message);
    std::vector<unsigned char> decrypted_message2 = bob_ratchet.get()->message_receive(*device_message2);

    EXPECT_EQ(decrypted_message.size(), 10);
    EXPECT_EQ(memcmp(decrypted_message.data(), plaintext_message, 10), 0);

    EXPECT_EQ(decrypted_message2.size(), 10);
    EXPECT_EQ(memcmp(decrypted_message2.data(), plaintext_message2, 10), 0);

    // now bob sends
    auto plaintext_message3 = new unsigned char[10];
    randombytes_buf(plaintext_message3, 10);
    DeviceMessage* device_message3 = bob_ratchet.get()->message_send(plaintext_message3);

    switch_to_alice_db();
    std::vector<unsigned char> decrypted_message3 = bob_ratchet.get()->message_receive(*device_message3);

    EXPECT_EQ(decrypted_message3.size(), 10);
    EXPECT_EQ(memcmp(decrypted_message3.data(), plaintext_message3, 10), 0);

    delete[] plaintext_message;
    delete[] plaintext_message2;
    delete[] plaintext_message3;
    delete device_message;
    delete device_message2;
    delete device_message3;
}

TEST_F(DoubleRatchetTest, MultipleMessageFromOneSideThenMultipleSwitchTest) {
    // alice ratchet
    switch_to_alice_db();
    std::unique_ptr<DoubleRatchet> alice_ratchet = std::make_unique<DoubleRatchet>(alice_sending_bundle);

    auto plaintext_message = new unsigned char[10];
    randombytes_buf(plaintext_message, 10);
    DeviceMessage* device_message = alice_ratchet.get()->message_send(plaintext_message);

    auto plaintext_message2 = new unsigned char[10];
    randombytes_buf(plaintext_message2, 10);
    DeviceMessage* device_message2 = alice_ratchet.get()->message_send(plaintext_message2);

    //bob ratchet
    switch_to_bob_db();
    std::unique_ptr<DoubleRatchet> bob_ratchet = std::make_unique<DoubleRatchet>(bob_receiving_bundle);

    std::vector<unsigned char> decrypted_message = bob_ratchet.get()->message_receive(*device_message);
    std::vector<unsigned char> decrypted_message2 = bob_ratchet.get()->message_receive(*device_message2);

    EXPECT_EQ(decrypted_message.size(), 10);
    EXPECT_EQ(memcmp(decrypted_message.data(), plaintext_message, 10), 0);

    EXPECT_EQ(decrypted_message2.size(), 10);
    EXPECT_EQ(memcmp(decrypted_message2.data(), plaintext_message2, 10), 0);

    // now bob sends
    auto plaintext_message3 = new unsigned char[10];
    randombytes_buf(plaintext_message3, 10);
    DeviceMessage* device_message3 = bob_ratchet.get()->message_send(plaintext_message3);

    switch_to_alice_db();
    std::vector<unsigned char> decrypted_message3 = bob_ratchet.get()->message_receive(*device_message3);

    EXPECT_EQ(decrypted_message3.size(), 10);
    EXPECT_EQ(memcmp(decrypted_message3.data(), plaintext_message3, 10), 0);

    //alice again

    switch_to_alice_db();

    auto plaintext_message4 = new unsigned char[10];
    randombytes_buf(plaintext_message4, 10);
    DeviceMessage* device_message4 = alice_ratchet.get()->message_send(plaintext_message4);

    //bob ratchet
    switch_to_bob_db();

    std::vector<unsigned char> decrypted_message4 = bob_ratchet.get()->message_receive(*device_message);

    delete[] plaintext_message;
    delete[] plaintext_message2;
    delete[] plaintext_message3;
    delete[] plaintext_message4;
    delete device_message;
    delete device_message2;
    delete device_message3;
    delete device_message4;
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
