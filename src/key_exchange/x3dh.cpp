#include "x3dh.h"
#include <sodium.h>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>

static std::string bin2hex(const unsigned char* bin, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)bin[i];
    return oss.str();
}

unsigned char* x3dh_initiator(
    const unsigned char* my_identity_key_private,
    const unsigned char* my_ephemeral_key_private,
    const unsigned char* recipient_identity_key_public,
    const unsigned char* recipient_signed_prekey_public,
    const unsigned char* recipient_onetime_prekey_public,
    const unsigned char* recipient_signed_prekey_signature,
    const unsigned char* recipient_ed25519_identity_key_public) {
    
    std::cout << "\n===== INITIATOR X3DH =====" << std::endl;
    
    if (recipient_signed_prekey_signature && recipient_ed25519_identity_key_public) {
        if (crypto_sign_verify_detached(
                recipient_signed_prekey_signature, 
                recipient_signed_prekey_public, 
                crypto_box_PUBLICKEYBYTES, 
                recipient_ed25519_identity_key_public) != 0) {
            throw std::runtime_error("Signature verification failed");
        }
        std::cout << "Signature verification successful" << std::endl;
    } else {
        throw std::runtime_error("No signature attached to x3dh key pair from server");
    }
    
    constexpr size_t KEY_LEN = crypto_scalarmult_BYTES;
    
    unsigned char dh1[KEY_LEN], dh2[KEY_LEN], dh3[KEY_LEN], dh4[KEY_LEN];
    
    if (crypto_scalarmult(dh1, my_identity_key_private, recipient_signed_prekey_public) != 0)
        throw std::runtime_error("DH1 failed");
    
    std::cout << "DH2 (Initiator): Using my ephemeral private key with recipient's identity public key\n";
    if (crypto_scalarmult(dh2, my_ephemeral_key_private, recipient_identity_key_public) != 0)
        throw std::runtime_error("DH2 failed");
    
    if (crypto_scalarmult(dh3, my_ephemeral_key_private, recipient_signed_prekey_public) != 0)
        throw std::runtime_error("DH3 failed");
    
    if (recipient_onetime_prekey_public && my_ephemeral_key_private) {
        if (crypto_scalarmult(dh4, my_ephemeral_key_private, recipient_onetime_prekey_public) != 0)
            throw std::runtime_error("DH4 failed");
    } else {
        memset(dh4, 0, KEY_LEN);
    }
    
    unsigned char ikm[KEY_LEN * 4];
    memcpy(ikm, dh1, KEY_LEN);
    memcpy(ikm + KEY_LEN, dh2, KEY_LEN);
    memcpy(ikm + 2 * KEY_LEN, dh3, KEY_LEN);
    memcpy(ikm + 3 * KEY_LEN, dh4, KEY_LEN);
    
    unsigned char* shared_secret = new unsigned char[KEY_LEN];
    crypto_generichash(shared_secret, KEY_LEN, ikm, sizeof(ikm), nullptr, 0);
    
    std::cout << "INITIATOR SHARED SECRETS:" << std::endl;
    std::cout << "DH1: " << bin2hex(dh1, KEY_LEN) << std::endl;
    std::cout << "DH2: " << bin2hex(dh2, KEY_LEN) << std::endl;
    std::cout << "DH3: " << bin2hex(dh3, KEY_LEN) << std::endl;
    std::cout << "DH4: " << bin2hex(dh4, KEY_LEN) << std::endl;
    
    std::cout << "\nFinal X3DH Shared Secret (Root Key): " << bin2hex(shared_secret, KEY_LEN) << std::endl;
    
    return shared_secret;
}

unsigned char* x3dh_responder(
    const unsigned char* initiator_identity_key_public,
    const unsigned char* initiator_ephemeral_key_public,
    const unsigned char* my_identity_key_private,
    const unsigned char* my_signed_prekey_private,
    const unsigned char* my_onetime_prekey_private) {
    
    std::cout << "\n===== RESPONDER X3DH =====" << std::endl;
    
    constexpr size_t KEY_LEN = crypto_scalarmult_BYTES;
    
    unsigned char dh1[KEY_LEN], dh2[KEY_LEN], dh3[KEY_LEN], dh4[KEY_LEN];
    
    if (crypto_scalarmult(dh1, my_signed_prekey_private, initiator_identity_key_public) != 0)
        throw std::runtime_error("DH1 failed");
    
    std::cout << "DH2 (Responder): Using my identity private key with initiator's ephemeral public key\n";
    if (crypto_scalarmult(dh2, my_identity_key_private, initiator_ephemeral_key_public) != 0)
        throw std::runtime_error("DH2 failed");
    
    if (crypto_scalarmult(dh3, my_signed_prekey_private, initiator_ephemeral_key_public) != 0)
        throw std::runtime_error("DH3 failed");
    
    if (my_onetime_prekey_private && initiator_ephemeral_key_public) {
        if (crypto_scalarmult(dh4, my_onetime_prekey_private, initiator_ephemeral_key_public) != 0)
            throw std::runtime_error("DH4 failed");
    } else {
        memset(dh4, 0, KEY_LEN);
    }
    
    unsigned char ikm[KEY_LEN * 4];
    memcpy(ikm, dh1, KEY_LEN);
    memcpy(ikm + KEY_LEN, dh2, KEY_LEN);
    memcpy(ikm + 2 * KEY_LEN, dh3, KEY_LEN);
    memcpy(ikm + 3 * KEY_LEN, dh4, KEY_LEN);
    
    unsigned char* shared_secret = new unsigned char[KEY_LEN];
    crypto_generichash(shared_secret, KEY_LEN, ikm, sizeof(ikm), nullptr, 0);
    
    std::cout << "RESPONDER SHARED SECRETS:" << std::endl;
    std::cout << "DH1: " << bin2hex(dh1, KEY_LEN) << std::endl;
    std::cout << "DH2: " << bin2hex(dh2, KEY_LEN) << std::endl;
    std::cout << "DH3: " << bin2hex(dh3, KEY_LEN) << std::endl;
    std::cout << "DH4: " << bin2hex(dh4, KEY_LEN) << std::endl;
    
    std::cout << "\nFinal X3DH Shared Secret (Root Key): " << bin2hex(shared_secret, KEY_LEN) << std::endl;
    
    return shared_secret;
}
