//
// Created by Josh Sloggett on 01/06/2025.
//

#ifndef RATCHETSESSIONMANAGER_H
#define RATCHETSESSIONMANAGER_H
#include <map>

#include "KeyBundle.h"
#include "src/key_exchange/NewRatchet.h"
#include "src/sql/queries.h"


class RatchetSessionManager{
public:
    RatchetSessionManager();

    void create_ratchets_if_needed(std::string username, std::vector<KeyBundle*> bundles);
    // device id : <key, message header>
    std::map<std::array<unsigned char, 32>, std::tuple<std::array<unsigned char, 32>, MessageHeader*>> get_keys_for_identity(std::string username);
    // essentially receive
    unsigned char* get_key_for_device(std::string username, MessageHeader* header);
private:
    // username : [ device_id : ratchet ]
    std::map<std::string, std::map<std::array<unsigned char, 32>, std::unique_ptr<NewRatchet>>> ratchets;
};



#endif //RATCHETSESSIONMANAGER_H
