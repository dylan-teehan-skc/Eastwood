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
    static RatchetSessionManager& instance();
    
    RatchetSessionManager();

    ~RatchetSessionManager();

    // Delete copy constructor and assignment operator to prevent copying
    RatchetSessionManager(const RatchetSessionManager&) = delete;
    RatchetSessionManager& operator=(const RatchetSessionManager&) = delete;

    void create_ratchets_if_needed(const std::string &username, const std::vector<KeyBundle*> &bundles, bool post_to_server = true);
    // device id : <key, message header>
    std::map<std::array<unsigned char, 32>, std::tuple<std::array<unsigned char, 32>, MessageHeader*>> get_keys_for_identity(const std::string &username, bool post_new_ratchets_to_server = true);
    // essentially receive
    unsigned char* get_key_for_device(const std::string &username, MessageHeader* header);

    void load_ratchets_from_db();

    std::vector<std::array<unsigned char,32>>get_device_ids_of_existing_handshakes(const std::string &username);
private:
    // username : [ device_id : ratchet ]
    std::map<std::string, std::map<std::array<unsigned char, 32>, std::unique_ptr<NewRatchet>>> ratchets;
};



#endif //RATCHETSESSIONMANAGER_H
