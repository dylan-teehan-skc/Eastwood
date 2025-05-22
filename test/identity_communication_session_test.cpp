#include <iostream>
#include <iomanip>
#include <sstream>
#include <sodium.h>
#include "src/key_exchange/utils.h"
#include <map>

struct keyBundle {
    bool isSending;
    unsigned char* device_key_public[32];
    unsigned char* device_key_private[32];

    unsigned char* ed25519_device_key_public[32];
    unsigned char* ed25519_device_key_private[64];

    unsigned char* ephemeral_key_public[32];
    unsigned char* ephemeral_key_private[32];

    unsigned char* signed_prekey_public[32];
    unsigned char* signed_prekey_private[32];
    unsigned char* signed_prekey_signature[64];

    unsigned char* onetime_prekey_public[32];
    unsigned char* onetime_prekey_private[32];
};

// Helper function to generate a key bundle
keyBundle generateKeyBundle(bool isSending) {
    keyBundle bundle;
    bundle.isSending = isSending;
    
    // Allocate memory for all keys
    *bundle.device_key_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
    *bundle.device_key_private = new unsigned char[crypto_box_SECRETKEYBYTES];
    
    *bundle.ed25519_device_key_public = new unsigned char[crypto_sign_PUBLICKEYBYTES];
    *bundle.ed25519_device_key_private = new unsigned char[crypto_sign_SECRETKEYBYTES];
    
    *bundle.ephemeral_key_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
    *bundle.ephemeral_key_private = new unsigned char[crypto_box_SECRETKEYBYTES];
    
    *bundle.signed_prekey_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
    *bundle.signed_prekey_private = new unsigned char[crypto_box_SECRETKEYBYTES];
    *bundle.signed_prekey_signature = new unsigned char[crypto_sign_BYTES];
    
    *bundle.onetime_prekey_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
    *bundle.onetime_prekey_private = new unsigned char[crypto_box_SECRETKEYBYTES];
    
    // Generate key pairs
    crypto_box_keypair(*bundle.device_key_public, *bundle.device_key_private);
    crypto_sign_keypair(*bundle.ed25519_device_key_public, *bundle.ed25519_device_key_private);
    crypto_box_keypair(*bundle.ephemeral_key_public, *bundle.ephemeral_key_private);
    crypto_box_keypair(*bundle.signed_prekey_public, *bundle.signed_prekey_private);
    crypto_box_keypair(*bundle.onetime_prekey_public, *bundle.onetime_prekey_private);
    
    // Sign the prekey
    crypto_sign_detached(
        *bundle.signed_prekey_signature,
        nullptr,
        *bundle.signed_prekey_public,
        crypto_box_PUBLICKEYBYTES,
        *bundle.ed25519_device_key_private
    );
    
    return bundle;
}

// Helper function to clean up a key bundle
void cleanupKeyBundle(keyBundle& bundle) {
    delete[] *bundle.device_key_public;
    delete[] *bundle.device_key_private;
    delete[] *bundle.ed25519_device_key_public;
    delete[] *bundle.ed25519_device_key_private;
    delete[] *bundle.ephemeral_key_public;
    delete[] *bundle.ephemeral_key_private;
    delete[] *bundle.signed_prekey_public;
    delete[] *bundle.signed_prekey_private;
    delete[] *bundle.signed_prekey_signature;
    delete[] *bundle.onetime_prekey_public;
    delete[] *bundle.onetime_prekey_private;
}

// Helper function to simulate device session ID creation
unsigned char* createDeviceSessionId(const unsigned char* device_id_1, const unsigned char* device_id_2, size_t& out_len) {
    return concat_ordered(device_id_1, crypto_box_PUBLICKEYBYTES, device_id_2, crypto_box_PUBLICKEYBYTES, out_len);
}

// Class to simulate a device communication session for testing
class MockDeviceSession {
public:
    MockDeviceSession(const unsigned char* local_device_id, const unsigned char* remote_device_id) {
        size_t session_id_len;
        session_id = createDeviceSessionId(local_device_id, remote_device_id, session_id_len);
        this->session_id_len = session_id_len;
    }
    
    ~MockDeviceSession() {
        delete[] session_id;
    }
    
    const unsigned char* getSessionId() const {
        return session_id;
    }
    
    size_t getSessionIdLen() const {
        return session_id_len;
    }
    
private:
    unsigned char* session_id;
    size_t session_id_len;
};

// Class to simulate an identity communication session for testing
class MockIdentitySession {
public:
    MockIdentitySession(const keyBundle& my_bundle, const std::string& owner_name) 
        : my_bundle(my_bundle), owner_name(owner_name) {}
    
    ~MockIdentitySession() {
        // Clean up all device sessions
        for (auto& pair : device_sessions) {
            delete pair.second;
        }
        device_sessions.clear();
    }
    
    // Create a new session with a remote device
    bool createSessionWithDevice(const keyBundle& remote_bundle, const std::string& remote_name) {
        // Create a unique session ID for this device pair
        std::string session_key = remote_name + ":" + bin2hex(*remote_bundle.device_key_public, crypto_box_PUBLICKEYBYTES);
        
        // Check if session already exists
        if (device_sessions.find(session_key) != device_sessions.end()) {
            std::cout << owner_name << " already has a session with " << remote_name 
                      << " device " << bin2hex(*remote_bundle.device_key_public, crypto_box_PUBLICKEYBYTES).substr(0, 8) 
                      << "..." << std::endl;
            return false;
        }
        
        // Create a new session
        MockDeviceSession* new_session = new MockDeviceSession(
            *my_bundle.device_key_public,
            *remote_bundle.device_key_public
        );
        
        // Store the session
        device_sessions[session_key] = new_session;
        
        std::cout << owner_name << " created a new session with " << remote_name 
                  << " device " << bin2hex(*remote_bundle.device_key_public, crypto_box_PUBLICKEYBYTES).substr(0, 8) 
                  << "..." << std::endl;
        
        return true;
    }
    
    // Get number of active sessions
    size_t getSessionCount() const {
        return device_sessions.size();
    }
    
    // Get a list of remote device names that have sessions
    std::vector<std::string> getSessionDevices() const {
        std::vector<std::string> devices;
        for (const auto& pair : device_sessions) {
            devices.push_back(pair.first);
        }
        return devices;
    }
    
private:
    keyBundle my_bundle;
    std::string owner_name;
    std::map<std::string, MockDeviceSession*> device_sessions;
};

void test_multi_device_session_management() {
    std::cout << "\n===== TESTING MULTI-DEVICE SESSION MANAGEMENT =====" << std::endl;
    
    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return;
    }
    
    try {
        // SETUP: Create devices for Alice and Bob
        std::cout << "\n--- SETUP: Creating devices ---" << std::endl;
        
        // Alice has 3 devices
        keyBundle alice_device1 = generateKeyBundle(true);  // Primary device
        keyBundle alice_device2 = generateKeyBundle(true);  // Secondary device
        keyBundle alice_device3 = generateKeyBundle(true);  // Tertiary device
        
        // Bob has 2 devices
        keyBundle bob_device1 = generateKeyBundle(true);    // Primary device
        keyBundle bob_device2 = generateKeyBundle(true);    // Secondary device
        
        std::cout << "Alice Primary Device: " << bin2hex(*alice_device1.device_key_public, crypto_box_PUBLICKEYBYTES).substr(0, 16) << "..." << std::endl;
        std::cout << "Alice Secondary Device: " << bin2hex(*alice_device2.device_key_public, crypto_box_PUBLICKEYBYTES).substr(0, 16) << "..." << std::endl;
        std::cout << "Alice Tertiary Device: " << bin2hex(*alice_device3.device_key_public, crypto_box_PUBLICKEYBYTES).substr(0, 16) << "..." << std::endl;
        std::cout << "Bob Primary Device: " << bin2hex(*bob_device1.device_key_public, crypto_box_PUBLICKEYBYTES).substr(0, 16) << "..." << std::endl;
        std::cout << "Bob Secondary Device: " << bin2hex(*bob_device2.device_key_public, crypto_box_PUBLICKEYBYTES).substr(0, 16) << "..." << std::endl;
        
        // SCENARIO 1: Alice initiates communication with Bob
        std::cout << "\n--- SCENARIO 1: Alice initiates communication with Bob ---" << std::endl;
        
        // Alice creates a session from her primary device
        MockIdentitySession alice_session(alice_device1, "Alice");
        
        // Alice should create one session per Bob device
        alice_session.createSessionWithDevice(bob_device1, "Bob");
        alice_session.createSessionWithDevice(bob_device2, "Bob");
        
        std::cout << "Alice has " << alice_session.getSessionCount() << " device sessions" << std::endl;
        
        // SCENARIO 2: Bob receives communication from Alice
        std::cout << "\n--- SCENARIO 2: Bob receives communication from Alice ---" << std::endl;
        
        // Bob creates a session from his primary device
        MockIdentitySession bob_session(bob_device1, "Bob");
        
        // Bob should create one session for the specific Alice device
        bob_session.createSessionWithDevice(alice_device1, "Alice");
        
        std::cout << "Bob has " << bob_session.getSessionCount() << " device sessions" << std::endl;
        
        // SCENARIO 3: Bob now wants to message Alice on all her devices
        std::cout << "\n--- SCENARIO 3: Bob messages all of Alice's devices ---" << std::endl;
        
        // Bob should retain the existing session and create new ones for Alice's other devices
        bool retained_session = !bob_session.createSessionWithDevice(alice_device1, "Alice"); // This should not create a new session
        bool created_session2 = bob_session.createSessionWithDevice(alice_device2, "Alice");
        bool created_session3 = bob_session.createSessionWithDevice(alice_device3, "Alice");
        
        std::cout << "Bob retained existing session: " << (retained_session ? "Yes" : "No") << std::endl;
        std::cout << "Bob created new session for Alice's device 2: " << (created_session2 ? "Yes" : "No") << std::endl;
        std::cout << "Bob created new session for Alice's device 3: " << (created_session3 ? "Yes" : "No") << std::endl;
        std::cout << "Bob now has " << bob_session.getSessionCount() << " device sessions" << std::endl;
        
        // SCENARIO 4: Alice receives from Bob's primary device and wants to respond to all Bob's devices
        std::cout << "\n--- SCENARIO 4: Alice receives and responds to all Bob's devices ---" << std::endl;
        
        // Alice should retain existing sessions and not create duplicates
        bool alice_retained1 = !alice_session.createSessionWithDevice(bob_device1, "Bob");
        bool alice_retained2 = !alice_session.createSessionWithDevice(bob_device2, "Bob");
        
        std::cout << "Alice retained session with Bob's device 1: " << (alice_retained1 ? "Yes" : "No") << std::endl;
        std::cout << "Alice retained session with Bob's device 2: " << (alice_retained2 ? "Yes" : "No") << std::endl;
        std::cout << "Alice still has " << alice_session.getSessionCount() << " device sessions" << std::endl;
        
        // Clean up key bundles
        cleanupKeyBundle(alice_device1);
        cleanupKeyBundle(alice_device2);
        cleanupKeyBundle(alice_device3);
        cleanupKeyBundle(bob_device1);
        cleanupKeyBundle(bob_device2);
        
        std::cout << "\n✅ Multi-device session management test completed successfully" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "❌ Error in test: " << e.what() << std::endl;
    }
    
    std::cout << "\n===== MULTI-DEVICE SESSION MANAGEMENT TEST COMPLETED =====" << std::endl;
}

int main() {
    test_multi_device_session_management();
    return 0;
} 