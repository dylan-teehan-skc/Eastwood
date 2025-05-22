#include "DeviceCommunicationSession.h"
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

DeviceSendingCommunicationSession::DeviceSendingCommunicationSession(
    const unsigned char* device_key_public,
    const unsigned char* device_key_private,
    const unsigned char* ephemeral_key_public,
    const unsigned char* ephemeral_key_private,
    const unsigned char* recipient_device_key_public,
    const unsigned char* recipient_signed_prekey_public,
    const unsigned char* recipient_onetime_prekey_public,
    const unsigned char* recipient_signed_prekey_signature,
    const unsigned char* recipient_ed25519_device_key_public) {
    
    std::cout << "\n===== INITIATOR KEYS BEFORE X3DH =====" << std::endl;
    print_key("My device Public Key", device_key_public, crypto_box_PUBLICKEYBYTES);
    print_key("My Ephemeral Public Key", ephemeral_key_public, crypto_box_PUBLICKEYBYTES);
    print_key("Recipient device Public Key", recipient_device_key_public, crypto_box_PUBLICKEYBYTES);
    print_key("Recipient Signed Prekey Public", recipient_signed_prekey_public, crypto_box_PUBLICKEYBYTES);
    
    shared_secret = x3dh_initiator(
        device_key_public,
        device_key_private,
        ephemeral_key_public,
        ephemeral_key_private,
        recipient_device_key_public,
        recipient_signed_prekey_public,
        recipient_onetime_prekey_public,
        recipient_signed_prekey_signature,
        recipient_ed25519_device_key_public // ed converted curve for verification
    );

    // SEND POST REQUET TO /handshake/identity_key
    // request contains;
    // recipients public signed prekey, recipients public onetime prekey
    // initiator (my) public device key, initiatior (my) public ephemeral key
    
    ratchet = std::make_unique<DoubleRatchet>(
        shared_secret,
        recipient_signed_prekey_public,
        ephemeral_key_public,
        ephemeral_key_private
    );
}

DeviceSendingCommunicationSession::~DeviceSendingCommunicationSession() {
    delete[] shared_secret;
}

const unsigned char* DeviceSendingCommunicationSession::getSharedSecret() const {
    return shared_secret;
}

DoubleRatchet* DeviceSendingCommunicationSession::getRatchet() {
    return ratchet.get();
}

DeviceReceivingCommunicationSession::DeviceReceivingCommunicationSession(
    const unsigned char* initiator_device_key_public,
    const unsigned char* initiator_ephemeral_key_public,
    const unsigned char* device_key_public,
    const unsigned char* device_key_private,
    const unsigned char* signed_prekey_public,
    const unsigned char* signed_prekey_private,
    const unsigned char* onetime_prekey_public,
    const unsigned char* onetime_prekey_private) {
    
    std::cout << "\n===== RESPONDER KEYS BEFORE X3DH =====" << std::endl;
    print_key("Initiator device Public Key", initiator_device_key_public, crypto_box_PUBLICKEYBYTES);
    print_key("Initiator Ephemeral Public Key", initiator_ephemeral_key_public, crypto_box_PUBLICKEYBYTES);
    print_key("My device Public Key", device_key_public, crypto_box_PUBLICKEYBYTES);
    print_key("My Signed Prekey Public", signed_prekey_public, crypto_box_PUBLICKEYBYTES);
    
    shared_secret = x3dh_responder(
        initiator_device_key_public,
        initiator_ephemeral_key_public,
        device_key_public,
        device_key_private,
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

DeviceReceivingCommunicationSession::~DeviceReceivingCommunicationSession() {
    delete[] shared_secret;
}

const unsigned char* DeviceReceivingCommunicationSession::getSharedSecret() const {
    return shared_secret;
}

DoubleRatchet* DeviceReceivingCommunicationSession::getRatchet() {
    return ratchet.get();
}
