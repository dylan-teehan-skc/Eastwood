#include "CommunicationSession.h"
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>

static void print_key(const char* name, const unsigned char* key, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)key[i];
    std::cout << name << ": " << oss.str() << std::endl;
}

SendingCommunicationSession::SendingCommunicationSession(
    const unsigned char* identity_key_public,
    const unsigned char* identity_key_private,
    const unsigned char* ephemeral_key_public,
    const unsigned char* ephemeral_key_private,
    const unsigned char* recipient_identity_key_public,
    const unsigned char* recipient_signed_prekey_public,
    const unsigned char* recipient_onetime_prekey_public,
    const unsigned char* recipient_signed_prekey_signature,
    const unsigned char* recipient_ed25519_identity_key_public) {
    
    std::cout << "\n===== INITIATOR KEYS BEFORE X3DH =====" << std::endl;
    print_key("My Identity Public Key", identity_key_public, crypto_box_PUBLICKEYBYTES);
    print_key("My Ephemeral Public Key", ephemeral_key_public, crypto_box_PUBLICKEYBYTES);
    print_key("Recipient Identity Public Key", recipient_identity_key_public, crypto_box_PUBLICKEYBYTES);
    print_key("Recipient Signed Prekey Public", recipient_signed_prekey_public, crypto_box_PUBLICKEYBYTES);
    
    shared_secret = x3dh_initiator(
        identity_key_public,
        identity_key_private,
        ephemeral_key_public,
        ephemeral_key_private,
        recipient_identity_key_public,
        recipient_signed_prekey_public,
        recipient_onetime_prekey_public,
        recipient_signed_prekey_signature,
        recipient_ed25519_identity_key_public // ed converted curve for verification
    );
    
    ratchet = std::make_unique<DoubleRatchet>(
        shared_secret,
        recipient_signed_prekey_public,
        ephemeral_key_public,
        ephemeral_key_private
    );
}

SendingCommunicationSession::~SendingCommunicationSession() {
    delete[] shared_secret;
}

const unsigned char* SendingCommunicationSession::getSharedSecret() const {
    return shared_secret;
}

DoubleRatchet* SendingCommunicationSession::getRatchet() {
    return ratchet.get();
}

ReceivingCommunicationSession::ReceivingCommunicationSession(
    const unsigned char* initiator_identity_key_public,
    const unsigned char* initiator_ephemeral_key_public,
    const unsigned char* identity_key_public,
    const unsigned char* identity_key_private,
    const unsigned char* signed_prekey_public,
    const unsigned char* signed_prekey_private,
    const unsigned char* onetime_prekey_public,
    const unsigned char* onetime_prekey_private) {
    
    std::cout << "\n===== RESPONDER KEYS BEFORE X3DH =====" << std::endl;
    print_key("Initiator Identity Public Key", initiator_identity_key_public, crypto_box_PUBLICKEYBYTES);
    print_key("Initiator Ephemeral Public Key", initiator_ephemeral_key_public, crypto_box_PUBLICKEYBYTES);
    print_key("My Identity Public Key", identity_key_public, crypto_box_PUBLICKEYBYTES);
    print_key("My Signed Prekey Public", signed_prekey_public, crypto_box_PUBLICKEYBYTES);
    
    shared_secret = x3dh_responder(
        initiator_identity_key_public,
        initiator_ephemeral_key_public,
        identity_key_public,
        identity_key_private,
        signed_prekey_public,
        signed_prekey_private,
        onetime_prekey_public,
        onetime_prekey_private
    );
    
    ratchet = std::make_unique<DoubleRatchet>(
        shared_secret,
        initiator_ephemeral_key_public,
        signed_prekey_public,
        signed_prekey_private
    );
}

ReceivingCommunicationSession::~ReceivingCommunicationSession() {
    delete[] shared_secret;
}

const unsigned char* ReceivingCommunicationSession::getSharedSecret() const {
    return shared_secret;
}

DoubleRatchet* ReceivingCommunicationSession::getRatchet() {
    return ratchet.get();
}
