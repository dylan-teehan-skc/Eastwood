#include <iostream>
#include <iomanip>
#include <sstream>
#include <sodium.h>
#include "cryptography/DoubleRatchet.h"
#include "cryptography/CommunicationSession.h"
#include "cryptography/x3dh.h"

std::string bin2hex(const unsigned char* bin, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)bin[i];
    return oss.str();
}

void test_communication_sessions() {
    std::cout << "\n===== TESTING COMMUNICATION SESSIONS =====" << std::endl;

    // Generate identity and ephemeral keys for Alice (initiator)
    unsigned char alice_identity_priv[crypto_box_SECRETKEYBYTES];
    unsigned char alice_identity_pub[crypto_box_PUBLICKEYBYTES];
    crypto_box_keypair(alice_identity_pub, alice_identity_priv);
    
    unsigned char alice_ephemeral_priv[crypto_box_SECRETKEYBYTES];
    unsigned char alice_ephemeral_pub[crypto_box_PUBLICKEYBYTES];
    crypto_box_keypair(alice_ephemeral_pub, alice_ephemeral_priv);
    
    // Generate identity and prekeys for Bob (responder)
    unsigned char bob_identity_priv[crypto_box_SECRETKEYBYTES];
    unsigned char bob_identity_pub[crypto_box_PUBLICKEYBYTES];
    crypto_box_keypair(bob_identity_pub, bob_identity_priv);
    
    unsigned char bob_signed_prekey_priv[crypto_box_SECRETKEYBYTES]; 
    unsigned char bob_signed_prekey_pub[crypto_box_PUBLICKEYBYTES];
    crypto_box_keypair(bob_signed_prekey_pub, bob_signed_prekey_priv);
    
    unsigned char bob_onetime_prekey_priv[crypto_box_SECRETKEYBYTES];
    unsigned char bob_onetime_prekey_pub[crypto_box_PUBLICKEYBYTES];
    crypto_box_keypair(bob_onetime_prekey_pub, bob_onetime_prekey_priv);
    
    // Generate Ed25519 keypair for Bob's signature
    unsigned char bob_ed25519_priv[crypto_sign_SECRETKEYBYTES];
    unsigned char bob_ed25519_pub[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_keypair(bob_ed25519_pub, bob_ed25519_priv);
    
    // Sign Bob's signed prekey using Ed25519 key
    unsigned char bob_signed_prekey_sig[crypto_sign_BYTES];
    crypto_sign_detached(
        bob_signed_prekey_sig,
        nullptr,
        bob_signed_prekey_pub,
        crypto_box_PUBLICKEYBYTES,
        bob_ed25519_priv
    );
    
    // Print keys for debugging
    std::cout << "Alice identity key: " << bin2hex(alice_identity_pub, crypto_box_PUBLICKEYBYTES) << std::endl;
    std::cout << "Alice ephemeral key: " << bin2hex(alice_ephemeral_pub, crypto_box_PUBLICKEYBYTES) << std::endl;
    std::cout << "Bob identity key: " << bin2hex(bob_identity_pub, crypto_box_PUBLICKEYBYTES) << std::endl;
    std::cout << "Bob signed prekey: " << bin2hex(bob_signed_prekey_pub, crypto_box_PUBLICKEYBYTES) << std::endl;
    std::cout << "Bob signed prekey signature: " << bin2hex(bob_signed_prekey_sig, crypto_sign_BYTES) << std::endl;
    std::cout << "Bob onetime prekey: " << bin2hex(bob_onetime_prekey_pub, crypto_box_PUBLICKEYBYTES) << std::endl;
    
    // Create Alice's sending session with all keys passed explicitly
    SendingCommunicationSession alice(
        alice_identity_pub,
        alice_identity_priv,
        alice_ephemeral_pub,
        alice_ephemeral_priv,
        bob_identity_pub,
        bob_signed_prekey_pub,
        bob_onetime_prekey_pub,
        bob_signed_prekey_sig,
        bob_ed25519_pub
    );
    
    // Create Bob's receiving session with all keys passed explicitly
    ReceivingCommunicationSession bob(
        alice_identity_pub,
        alice_ephemeral_pub,
        bob_identity_pub,
        bob_identity_priv,
        bob_signed_prekey_pub,
        bob_signed_prekey_priv,
        bob_onetime_prekey_pub,
        bob_onetime_prekey_priv
    );
    
    // Verify the shared secrets match
    std::cout << "\nAlice's shared secret: " << bin2hex(alice.getSharedSecret(), KEY_LEN) << std::endl;
    std::cout << "Bob's shared secret: " << bin2hex(bob.getSharedSecret(), KEY_LEN) << std::endl;
    
    bool shared_secrets_match = (memcmp(alice.getSharedSecret(), bob.getSharedSecret(), KEY_LEN) == 0);
    std::cout << "Shared secrets match: " << (shared_secrets_match ? "YES" : "NO") << std::endl;
    
    // Test Double Ratchet message exchange
    std::cout << "\n-- Testing Double Ratchet Message Exchange --" << std::endl;
    
    unsigned char* alice_message_key = alice.getRatchet()->message_send();
    std::cout << "Alice message key: " << bin2hex(alice_message_key, crypto_kdf_KEYBYTES) << std::endl;
    std::cout << "Alice's new public key: " << bin2hex(alice.getRatchet()->get_public_key(), crypto_kx_PUBLICKEYBYTES) << std::endl;
    
    unsigned char* bob_message_key = bob.getRatchet()->message_receive(alice.getRatchet()->get_public_key());
    std::cout << "Bob message key: " << bin2hex(bob_message_key, crypto_kdf_KEYBYTES) << std::endl;
    
    bool message_keys_match = (memcmp(alice_message_key, bob_message_key, crypto_kdf_KEYBYTES) == 0);
    std::cout << "Message keys match: " << (message_keys_match ? "YES" : "NO") << std::endl;
    
    unsigned char* bob_response_key = bob.getRatchet()->message_send();
    std::cout << "\nBob response key: " << bin2hex(bob_response_key, crypto_kdf_KEYBYTES) << std::endl;
    std::cout << "Bob's new public key: " << bin2hex(bob.getRatchet()->get_public_key(), crypto_kx_PUBLICKEYBYTES) << std::endl;
    
    unsigned char* alice_response_key = alice.getRatchet()->message_receive(bob.getRatchet()->get_public_key());
    std::cout << "Alice response key: " << bin2hex(alice_response_key, crypto_kdf_KEYBYTES) << std::endl;
    
    bool response_keys_match = (memcmp(bob_response_key, alice_response_key, crypto_kdf_KEYBYTES) == 0);
    std::cout << "Response keys match: " << (response_keys_match ? "YES" : "NO") << std::endl;
    
    // Clean up
    delete[] alice_message_key;
    delete[] bob_message_key;
    delete[] bob_response_key;
    delete[] alice_response_key;
}

int main(int argc, char *argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }
    
    test_communication_sessions();
    
    return 0;
}