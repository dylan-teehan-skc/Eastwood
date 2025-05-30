//
// Created by Josh Sloggett on 28/05/2025.
//

#ifndef IDENTITYSESSION_H
#define IDENTITYSESSION_H
#include <vector>
#include <memory>
#include <array>
#include "KeyBundle.h"
#include "src/key_exchange/DoubleRatchet.h"


class IdentitySession {
public:
    IdentitySession(std::vector<KeyBundle*> const &keys, const unsigned char* identity_session_id_in);
    ~IdentitySession();

    void updateFromBundles(std::vector<KeyBundle*> bundles);
    void send_message(unsigned char* message);
    void receive_message(DeviceMessage* message);

private:
    std::array<unsigned char, crypto_hash_sha256_BYTES> identity_session_id;
    std::map<std::array<unsigned char, crypto_box_PUBLICKEYBYTES * 2>, std::unique_ptr<DoubleRatchet>> ratchets;
    void create_ratchet_if_needed(const unsigned char* device_id_one, const unsigned char* device_id_two, KeyBundle* bundle);
};



#endif //IDENTITYSESSION_H
