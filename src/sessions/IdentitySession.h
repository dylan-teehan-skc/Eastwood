//
// Created by Josh Sloggett on 28/05/2025.
//

#ifndef IDENTITYSESSION_H
#define IDENTITYSESSION_H
#include <vector>
#include <memory>
#include "KeyBundle.h"
#include "src/key_exchange/DoubleRatchet.h"


class IdentitySession {
public:
    IdentitySession(std::vector<KeyBundle*> const &keys, unsigned char* identity_session_id_in);


    void updateFromBundles(std::vector<KeyBundle*> bundles);
private:
    unsigned char* identity_session_id;
    std::map<unsigned char*, std::unique_ptr<DoubleRatchet>> ratchets;
    void create_ratchet_if_needed(const unsigned char* device_id_one, const unsigned char* device_id_two, KeyBundle* bundle);
};



#endif //IDENTITYSESSION_H
