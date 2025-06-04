//
// Created by Josh Sloggett on 30/05/2025.
//

#ifndef NEWRATCHET_H
#define NEWRATCHET_H
#include <memory>
#include <unordered_map>
#include "MessageStructs.h"
#include "src/keys/secure_memory_buffer.h"
#include <vector>
#include <string>

struct NewChain {
    int index = 0;
    std::array<unsigned char, 32> key;
};

class NewRatchet {
public:
    NewRatchet(const std::array<unsigned char, 32> shared_secret, const std::array<unsigned char, 32> other_key);

    // Overload for initiator: pass ephemeral pub/priv
    NewRatchet(const std::array<unsigned char, 32> shared_secret, const std::array<unsigned char, 32> other_key,
               const std::array<unsigned char, 32> my_ephemeral_public, const std::shared_ptr<SecureMemoryBuffer> &my_ephemeral_private);
    NewRatchet(const std::vector<unsigned char, std::allocator<unsigned char>> &serialised_ratchet);

    ~NewRatchet() {
        skipped_keys.clear();
    }

    std::tuple<std::array<unsigned char,32>, MessageHeader> advance_send();
    std::array<unsigned char, 32> advance_receive(const MessageHeader header);

    std::tuple<int,int> get_chain_lengths();

    const std::array<unsigned char, 32> get_current_dh_public() const; //testing!!
    
    void save(const std::string& username, const std::array<unsigned char, 32>& device_id);

private:

    bool reversed;
    bool due_to_send_new_dh;
    std::array<unsigned char, 32> root_key;

    NewChain send_chain;
    NewChain receive_chain;

    // initiator -> fresh
    // recipient -> recipient signed prekey pair
    std::array<unsigned char, 32> local_dh_public;
    std::unique_ptr<SecureMemoryBuffer> local_dh_priv = SecureMemoryBuffer::create(32);

    // initiator -> receiver signed prekey
    // recipient -> initiator ephemeral
    std::array<unsigned char, 32> remote_dh_public;

    std::unordered_map<int, std::array<unsigned char, 32>> skipped_keys;
    int prev_chain_length;

    //methods
    // Overload for initiator: pass ephemeral pub/priv
    void set_up_initial_state_for_initiator(const std::array<unsigned char, 32> recipient_signed_public,
                                            const std::array<unsigned char, 32> my_ephemeral_public,
                                            std::shared_ptr<SecureMemoryBuffer> my_ephemeral_private);
    void set_up_initial_state_for_recipient(const std::array<unsigned char, 32> initiator_ephemeral_public);
    void set_up_initial_chain_keys();
    void generate_new_local_dh_keypair();

    void dh_ratchet_step(bool received_new_dh);
    std::array<unsigned char, 32> progress_receive_ratchet();
    std::tuple<std::array<unsigned char, 32>, MessageHeader> progress_sending_ratchet();

    // dh output of local dh private * remote dh public
    std::unique_ptr<unsigned char[]> dh() const;

    //serialisation
    void serialise(std::ostream& os) const;
    void deserialise(std::istream &in);

    friend class DoubleRatchetTest_Serialisation_Test;
    friend class DoubleRatchetTest_SavingAndLoadingFromDB_Test;
};



#endif //NEWRATCHET_H
