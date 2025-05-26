#include <iostream>
#include <sodium.h>
#include <fstream>
#include <cereal/cereal.hpp>
#include <cereal/archives/json.hpp>
#include "src/key_exchange/DeviceCommunicationSession.h"
#include "src/key_exchange/DoubleRatchet.h"

void test_device_communication_session_serialization() {
    std::cout << "\n===== TESTING DEVICE COMMUNICATION SESSION SERIALIZATION =====" << std::endl;
    
    // Initialize libsodium
    int sodium_result = sodium_init();
    std::cout << "sodium_init() returned: " << sodium_result << std::endl;
    if (sodium_result < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return;
    }
    std::cout << "About to call first crypto_kx_keypair..." << std::endl;
    
    try {
        // Generate Alice's keys (initiator)
        std::vector<unsigned char> alice_id_pk(crypto_kx_PUBLICKEYBYTES), alice_id_sk(crypto_kx_SECRETKEYBYTES);
        std::vector<unsigned char> alice_eph_pk(crypto_kx_PUBLICKEYBYTES), alice_eph_sk(crypto_kx_SECRETKEYBYTES);
        crypto_kx_keypair(alice_id_pk.data(), alice_id_sk.data());
        crypto_kx_keypair(alice_eph_pk.data(), alice_eph_sk.data());

        // Generate Bob's keys (responder)
        std::vector<unsigned char> bob_id_pk(crypto_kx_PUBLICKEYBYTES), bob_id_sk(crypto_kx_SECRETKEYBYTES);
        std::vector<unsigned char> bob_spk_pk(crypto_kx_PUBLICKEYBYTES), bob_spk_sk(crypto_kx_SECRETKEYBYTES);
        std::vector<unsigned char> bob_opk_pk(crypto_kx_PUBLICKEYBYTES), bob_opk_sk(crypto_kx_SECRETKEYBYTES);
        std::vector<unsigned char> bob_ed_pk(crypto_sign_PUBLICKEYBYTES), bob_ed_sk(crypto_sign_SECRETKEYBYTES);
        std::vector<unsigned char> bob_spk_sig(crypto_sign_BYTES);
        crypto_kx_keypair(bob_id_pk.data(), bob_id_sk.data());
        crypto_kx_keypair(bob_spk_pk.data(), bob_spk_sk.data());
        crypto_kx_keypair(bob_opk_pk.data(), bob_opk_sk.data());
        crypto_sign_keypair(bob_ed_pk.data(), bob_ed_sk.data());
        crypto_sign_detached(bob_spk_sig.data(), nullptr, bob_spk_pk.data(), bob_spk_pk.size(), bob_ed_sk.data());

        // Alice (initiator/sender)
        DeviceSendingCommunicationSession sending_session(
            alice_id_pk.data(),
            alice_id_sk.data(),
            alice_eph_pk.data(),
            alice_eph_sk.data(),
            bob_id_pk.data(),
            bob_spk_pk.data(),
            bob_opk_pk.data(),
            bob_spk_sig.data(),
            bob_ed_pk.data()
        );
        
        // Save the sending session
        std::string sending_filename = "test_sending_session.json";
        {
            std::ofstream ofs(sending_filename);
            cereal::JSONOutputArchive oarchive(ofs);
            oarchive(sending_session);
        }
        
        // Load the sending session
        DeviceSendingCommunicationSession loaded_sending_session;
        {
            std::ifstream ifs(sending_filename);
            cereal::JSONInputArchive iarchive(ifs);
            iarchive(loaded_sending_session);
        }
        
        // Bob (responder/receiver)
        DeviceReceivingCommunicationSession receiving_session(
            alice_id_pk.data(),
            alice_eph_pk.data(),
            bob_id_pk.data(),
            bob_id_sk.data(),
            bob_spk_pk.data(),
            bob_spk_sk.data(),
            bob_opk_sk.data()
        );
        
        // Save the receiving session
        std::string receiving_filename = "test_receiving_session.json";
        {
            std::ofstream ofs(receiving_filename);
            cereal::JSONOutputArchive oarchive(ofs);
            oarchive(receiving_session);
        }
        
        // Load the receiving session
        DeviceReceivingCommunicationSession loaded_receiving_session;
        {
            std::ifstream ifs(receiving_filename);
            cereal::JSONInputArchive iarchive(ifs);
            iarchive(loaded_receiving_session);
        }
        
        // Print the root keys for debugging
        std::cout << "\nSending session root key: ";
        const auto& sending_root_key = loaded_sending_session.getRatchet()->getRootKey();
        for (unsigned char i : sending_root_key) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
        }
        std::cout << std::endl;
        
        std::cout << "Receiving session root key: ";
        const auto& receiving_root_key = loaded_receiving_session.getRatchet()->getRootKey();
        for (unsigned char i : receiving_root_key) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
        }
        std::cout << std::endl;
        
        // Test sending a message through the loaded sending session
        const char* test_message = "Hello, this is a test message!";
        DeviceMessage encrypted = loaded_sending_session.getRatchet()->message_send((unsigned char*)test_message);
        
        // Test receiving the message through the loaded receiving session
        std::vector<unsigned char> decrypted = loaded_receiving_session.getRatchet()->message_receive(encrypted);
        std::string decrypted_str(decrypted.begin(), decrypted.end());
        
        if (decrypted_str == test_message) {
            std::cout << "✅ Device communication session serialization test passed!" << std::endl;
        } else {
            std::cout << "❌ Device communication session serialization test failed!" << std::endl;
            std::cout << "Original message: " << test_message << std::endl;
            std::cout << "Decrypted message: " << decrypted_str << std::endl;
            
            // Print more debug information
            std::cout << "\nDebug Information:" << std::endl;
            std::cout << "Sending session shared secret: ";
            const auto& sending_shared_secret = loaded_sending_session.getSharedSecret();
            for (unsigned char i : sending_shared_secret) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
            }
            std::cout << std::endl;
            
            std::cout << "Receiving session shared secret: ";
            const auto& receiving_shared_secret = loaded_receiving_session.getSharedSecret();
            for (unsigned char i : receiving_shared_secret) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
            }
            std::cout << std::endl;
        }

        // --- NEW: Serialize both sessions after first message exchange ---
        std::string sending_filename2 = "test_sending_session2.json";
        std::string receiving_filename2 = "test_receiving_session2.json";
        {
            std::ofstream ofs(sending_filename2);
            cereal::JSONOutputArchive oarchive(ofs);
            oarchive(loaded_sending_session);
        }
        {
            std::ofstream ofs(receiving_filename2);
            cereal::JSONOutputArchive oarchive(ofs);
            oarchive(loaded_receiving_session);
        }

        // --- NEW: Deserialize both sessions ---
        DeviceSendingCommunicationSession deserialized_sending_session;
        DeviceReceivingCommunicationSession deserialized_receiving_session;
        {
            std::ifstream ifs(sending_filename2);
            cereal::JSONInputArchive iarchive(ifs);
            iarchive(deserialized_sending_session);
        }
        {
            std::ifstream ifs(receiving_filename2);
            cereal::JSONInputArchive iarchive(ifs);
            iarchive(deserialized_receiving_session);
        }

        // --- NEW: Continue conversation ---
        const char* test_message2 = "Second message after serialization!";
        DeviceMessage encrypted2 = deserialized_sending_session.getRatchet()->message_send((unsigned char*)test_message2);
        std::vector<unsigned char> decrypted2 = deserialized_receiving_session.getRatchet()->message_receive(encrypted2);
        std::string decrypted_str2(decrypted2.begin(), decrypted2.end());
        if (decrypted_str2 == test_message2) {
            std::cout << "✅ Serialization round-trip test passed!" << std::endl;
        } else {
            std::cout << "❌ Serialization round-trip test failed!" << std::endl;
            std::cout << "Original message: " << test_message2 << std::endl;
            std::cout << "Decrypted message: " << decrypted_str2 << std::endl;
        }

        // Clean up
        std::filesystem::remove(sending_filename);
        std::filesystem::remove(receiving_filename);
        std::filesystem::remove(sending_filename2);
        std::filesystem::remove(receiving_filename2);
        
    } catch (const std::exception& e) {
        std::cerr << "Error during serialization test: " << e.what() << std::endl;
    }
    
    std::cout << "\n===== DEVICE COMMUNICATION SESSION SERIALIZATION TEST COMPLETED =====" << std::endl;
}

int main() {
    test_device_communication_session_serialization();
    return 0;
} 