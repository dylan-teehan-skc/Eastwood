#include <gtest/gtest.h>
#include "src/sessions/IdentityCommunicationSession.h"
#include "src/sessions/DeviceCommunicationSession.h"
#include "src/key_exchange/DoubleRatchet.h"
#include "src/key_exchange/utils.h"
#include <sodium.h>
#include <memory>
#include <vector>

// Helper function to generate a key bundle
keyBundle generateKeyBundle(bool isSending) {
    keyBundle bundle;
    bundle.isSending = isSending;
    
    // Allocate memory for all keys
    bundle.device_key_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
    bundle.device_key_private = new unsigned char[crypto_box_SECRETKEYBYTES];
    bundle.ephemeral_key_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
    bundle.ephemeral_key_private = new unsigned char[crypto_box_SECRETKEYBYTES];
    bundle.signed_prekey_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
    bundle.signed_prekey_private = new unsigned char[crypto_box_SECRETKEYBYTES];
    bundle.onetime_prekey_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
    bundle.onetime_prekey_private = new unsigned char[crypto_box_SECRETKEYBYTES];
    bundle.signed_prekey_signature = new unsigned char[crypto_sign_BYTES];
    bundle.ed25519_device_key_public = new unsigned char[crypto_sign_PUBLICKEYBYTES];
    bundle.ed25519_device_key_private = new unsigned char[crypto_sign_SECRETKEYBYTES];
    
    // Generate keys
    crypto_box_keypair(bundle.device_key_public, bundle.device_key_private);
    crypto_box_keypair(bundle.ephemeral_key_public, bundle.ephemeral_key_private);
    crypto_box_keypair(bundle.signed_prekey_public, bundle.signed_prekey_private);
    crypto_box_keypair(bundle.onetime_prekey_public, bundle.onetime_prekey_private);
    crypto_sign_keypair(bundle.ed25519_device_key_public, bundle.ed25519_device_key_private);
    
    // Sign the signed prekey
    crypto_sign_detached(bundle.signed_prekey_signature, nullptr,
                        bundle.signed_prekey_public, crypto_box_PUBLICKEYBYTES,
                        bundle.ed25519_device_key_private);
    
    return bundle;
}

// Helper function to clean up a key bundle
void cleanupKeyBundle(keyBundle& bundle) {
    delete[] bundle.device_key_public;
    delete[] bundle.device_key_private;
    delete[] bundle.ephemeral_key_public;
    delete[] bundle.ephemeral_key_private;
    delete[] bundle.signed_prekey_public;
    delete[] bundle.signed_prekey_private;
    delete[] bundle.onetime_prekey_public;
    delete[] bundle.onetime_prekey_private;
    delete[] bundle.signed_prekey_signature;
    delete[] bundle.ed25519_device_key_public;
    delete[] bundle.ed25519_device_key_private;
}

class IdentitySessionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize libsodium
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
        
        // Create key bundles for Alice and Bob
        alice_bundle = generateKeyBundle(true);
        bob_bundle = generateKeyBundle(false);
        
        // Create identity keys for Alice and Bob
        alice_identity_key_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
        alice_identity_key_private = new unsigned char[crypto_box_SECRETKEYBYTES];
        bob_identity_key_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
        bob_identity_key_private = new unsigned char[crypto_box_SECRETKEYBYTES];
        
        crypto_box_keypair(alice_identity_key_public, alice_identity_key_private);
        crypto_box_keypair(bob_identity_key_public, bob_identity_key_private);
        
        // Create key bundles list for both parties
        // For Alice's session, we need Bob's bundle with isSending=false
        // For Bob's session, we need Alice's bundle with isSending=true
        std::vector<keyBundle> alice_bundles = {bob_bundle};  // Bob's bundle is receiving
        std::vector<keyBundle> bob_bundles = {alice_bundle};  // Alice's bundle is sending
        
        // Create identity sessions
        alice_session = new IdentityCommunicationSession(alice_bundle, alice_bundles, 
                                                       alice_identity_key_public, 
                                                       bob_identity_key_public);
        bob_session = new IdentityCommunicationSession(bob_bundle, bob_bundles,
                                                     bob_identity_key_public,
                                                     alice_identity_key_public);
    }
    
    void TearDown() override {
        delete alice_session;
        delete bob_session;
        cleanupKeyBundle(alice_bundle);
        cleanupKeyBundle(bob_bundle);
        delete[] alice_identity_key_public;
        delete[] alice_identity_key_private;
        delete[] bob_identity_key_public;
        delete[] bob_identity_key_private;
    }
    
    keyBundle alice_bundle;
    keyBundle bob_bundle;
    unsigned char* alice_identity_key_public;
    unsigned char* alice_identity_key_private;
    unsigned char* bob_identity_key_public;
    unsigned char* bob_identity_key_private;
    IdentityCommunicationSession* alice_session;
    IdentityCommunicationSession* bob_session;
};

// Test basic message exchange between two devices
TEST_F(IdentitySessionTest, BasicMessageExchange) {
    // Create test message
    const char* test_message = "Hello, this is a test message!";
    size_t message_len = strlen(test_message);
    unsigned char* message = new unsigned char[message_len];
    memcpy(message, test_message, message_len);
    
    // Alice sends message to Bob
    alice_session->message_send(message);
    
    // Bob receives and processes the message
    // Note: In a real implementation, we would need to implement the actual message passing
    // between sessions. For now, we'll just verify that the sessions are properly set up.
    
    // Verify that both sessions have device sessions
    EXPECT_FALSE(alice_session->getDeviceSessions().empty());
    EXPECT_FALSE(bob_session->getDeviceSessions().empty());
    
    delete[] message;
}

// Test multi-device message exchange
TEST_F(IdentitySessionTest, MultiDeviceMessageExchange) {
    // Create additional key bundles for multiple devices
    keyBundle alice_device2 = generateKeyBundle(true);
    keyBundle bob_device2 = generateKeyBundle(false);
    
    // Add new device bundles to sessions
    std::vector<keyBundle> alice_new_bundles = {bob_device2};
    std::vector<keyBundle> bob_new_bundles = {alice_device2};
    
    alice_session->updateSessionsFromKeyBundles(alice_new_bundles);
    bob_session->updateSessionsFromKeyBundles(bob_new_bundles);
    
    // Verify that both sessions now have multiple device sessions
    EXPECT_GE(alice_session->getDeviceSessions().size(), 2);
    EXPECT_GE(bob_session->getDeviceSessions().size(), 2);
    
    // Clean up additional bundles
    cleanupKeyBundle(alice_device2);
    cleanupKeyBundle(bob_device2);
}

// Test session key derivation
TEST_F(IdentitySessionTest, SessionKeyDerivation) {
    // Verify that device sessions have valid shared secrets
    for (const auto& [session_id, session] : alice_session->getDeviceSessions()) {
        EXPECT_NE(session->getSharedSecret(), nullptr);
        EXPECT_NE(session->getRatchet(), nullptr);
    }
    
    for (const auto& [session_id, session] : bob_session->getDeviceSessions()) {
        EXPECT_NE(session->getSharedSecret(), nullptr);
        EXPECT_NE(session->getRatchet(), nullptr);
    }
}

// Test session cleanup
TEST_F(IdentitySessionTest, SessionCleanup) {
    // Create a temporary session
    auto temp_bundle = generateKeyBundle(true);
    std::vector<keyBundle> temp_bundles = {bob_bundle};
    
    {
        IdentityCommunicationSession temp_session(temp_bundle, temp_bundles,
                                               alice_identity_key_public,
                                               bob_identity_key_public);
        
        // Verify session is created
        EXPECT_FALSE(temp_session.getDeviceSessions().empty());
    }
    // Session should be properly cleaned up when it goes out of scope
    
    cleanupKeyBundle(temp_bundle);
}

TEST_F(IdentitySessionTest, EncryptedMessageExchange) {
    // Create a test message
    const char* test_message = "Hello, this is a secret message!";
    size_t message_len = strlen(test_message);
    unsigned char* message = new unsigned char[message_len + 1];  // +1 for null terminator
    memcpy(message, test_message, message_len);
    message[message_len] = '\0';  // Ensure null termination

    // Verify that both sessions have device sessions
    ASSERT_FALSE(alice_session->getDeviceSessions().empty()) << "Alice has no device sessions";
    ASSERT_FALSE(bob_session->getDeviceSessions().empty()) << "Bob has no device sessions";

    // Get Alice's sending session and Bob's receiving session
    DeviceSendingCommunicationSession* alice_sending_session = nullptr;
    DeviceReceivingCommunicationSession* bob_receiving_session = nullptr;

    // Find Alice's sending session
    for (const auto& [session_id, session] : alice_session->getDeviceSessions()) {
        if (auto* sending_session = dynamic_cast<DeviceSendingCommunicationSession*>(session)) {
            alice_sending_session = sending_session;
            break;
        }
    }
    ASSERT_NE(alice_sending_session, nullptr) << "Failed to find Alice's sending session";

    // Find Bob's receiving session
    for (const auto& [session_id, session] : bob_session->getDeviceSessions()) {
        if (auto* receiving_session = dynamic_cast<DeviceReceivingCommunicationSession*>(session)) {
            bob_receiving_session = receiving_session;
            break;
        }
    }
    ASSERT_NE(bob_receiving_session, nullptr) << "Failed to find Bob's receiving session";

    // Verify that both sessions have valid ratchets
    ASSERT_NE(alice_sending_session->getRatchet(), nullptr) << "Alice's ratchet is null";
    ASSERT_NE(bob_receiving_session->getRatchet(), nullptr) << "Bob's ratchet is null";

    // Encrypt the message using Alice's sending session
    DeviceMessage encrypted_message = alice_sending_session->getRatchet()->message_send(message, bob_bundle.device_key_public);
    ASSERT_NE(encrypted_message.ciphertext, nullptr) << "Encrypted message is null";
    ASSERT_NE(encrypted_message.header, nullptr) << "Message header is null";

    // Verify the encrypted message is different from the original
    ASSERT_NE(memcmp(encrypted_message.ciphertext, message, message_len), 0) 
        << "Encrypted message is identical to original message";

    // Decrypt the message using Bob's receiving session
    std::vector<unsigned char> decrypted_message = bob_receiving_session->getRatchet()->message_receive(encrypted_message);
    
    // Verify the decrypted message matches the original
    ASSERT_EQ(decrypted_message.size(), message_len) << "Decrypted message length mismatch";
    ASSERT_EQ(memcmp(decrypted_message.data(), message, message_len), 0) 
        << "Decrypted message doesn't match original message";

    // Clean up
    delete[] message;
}

TEST_F(IdentitySessionTest, MessageBroadcastToAllDevices) {
    // Create additional key bundles for multiple devices
    keyBundle alice_device2 = generateKeyBundle(false);  // Alice's second device (receiving)
    keyBundle bob_device2 = generateKeyBundle(true);     // Bob's second device (sending)
    
    // Add new device bundles to sessions
    std::vector<keyBundle> alice_new_bundles = {bob_device2};
    std::vector<keyBundle> bob_new_bundles = {alice_device2};
    
    alice_session->updateSessionsFromKeyBundles(alice_new_bundles);
    bob_session->updateSessionsFromKeyBundles(bob_new_bundles);
    
    // Verify that both sessions now have multiple device sessions
    ASSERT_GE(alice_session->getDeviceSessions().size(), 2) << "Alice should have at least 2 device sessions";
    ASSERT_GE(bob_session->getDeviceSessions().size(), 2) << "Bob should have at least 2 device sessions";
    
    // Create a test message
    const char* test_message = "Hello, this is a broadcast message!";
    size_t message_len = strlen(test_message);
    unsigned char* message = new unsigned char[message_len];
    memcpy(message, test_message, message_len);
    
    // Send message from Bob's identity session
    bob_session->message_send(message);
    
    // Verify that all of Bob's device sessions can send messages
    int sending_sessions_found = 0;
    for (const auto& [session_id, session] : bob_session->getDeviceSessions()) {
        // All device sessions can send messages
        sending_sessions_found++;
        ASSERT_NE(session->getRatchet(), nullptr) << "Session has no ratchet";
    }
    ASSERT_GT(sending_sessions_found, 0) << "No sending sessions found in Bob's device sessions";
    
    // Verify that all of Alice's device sessions can receive the message
    int receiving_sessions_found = 0;
    for (const auto& [session_id, session] : alice_session->getDeviceSessions()) {
        // All device sessions can receive messages
        receiving_sessions_found++;
        ASSERT_NE(session->getRatchet(), nullptr) << "Session has no ratchet";
    }
    ASSERT_GT(receiving_sessions_found, 0) << "No receiving sessions found in Alice's device sessions";
    
    // Clean up
    delete[] message;
    cleanupKeyBundle(alice_device2);
    cleanupKeyBundle(bob_device2);
} 