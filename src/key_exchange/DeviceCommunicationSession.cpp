#include "DeviceCommunicationSession.h"
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include "utils.h"

static void print_key(const char* name, const unsigned char* key, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)key[i];
    std::cout << name << ": " << oss.str() << std::endl;
}

DeviceCommunicationSession::DeviceCommunicationSession() 
    : shared_secret(nullptr), ratchet(nullptr), device_session_id(nullptr) {
    // Initialize base class - common functionality can be implemented here
    std::cout << "\n===== INITIALIZING DEVICE COMMUNICATION SESSION =====" << std::endl;
}

DeviceCommunicationSession::~DeviceCommunicationSession() {
    // Base class destructor - will be called after derived class destructors
}

unsigned char* DeviceCommunicationSession::getDeviceSessionId() {
    return device_session_id;
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
    const unsigned char* recipient_ed25519_device_key_public
) : DeviceCommunicationSession() {

    size_t device_session_key_len = sizeof(device_key_public) + sizeof(recipient_device_key_public);
    device_session_id = concat_ordered(device_key_public, crypto_box_PUBLICKEYBYTES, recipient_device_key_public, crypto_box_PUBLICKEYBYTES, device_session_key_len);

    shared_secret = x3dh_initiator(
        device_key_private,
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
    const unsigned char* onetime_prekey_private
) : DeviceCommunicationSession() {
    size_t device_session_key_len = sizeof(device_key_public) + sizeof(initiator_device_key_public);
    device_session_id = concat_ordered(device_key_public, crypto_box_PUBLICKEYBYTES, initiator_device_key_public, crypto_box_PUBLICKEYBYTES, device_session_key_len);
    shared_secret = x3dh_responder(
        initiator_device_key_public,
        initiator_ephemeral_key_public,
        device_key_private,
        signed_prekey_private,
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
