//
// Created by Josh Sloggett on 30/05/2025.
//

#ifndef NEWRATCHET_H
#define NEWRATCHET_H
#include <memory>
#include <unordered_map>
#include "MessageStructs.h"
#include "src/keys/secure_memory_buffer.h"

struct NewChain {
    int index = 0;
    unsigned char key[32];
};

class NewRatchet {
public:
    NewRatchet(const unsigned char* shared_secret, const unsigned char* other_key, bool is_sender);
    NewRatchet(std::istream& in);

    std::tuple<unsigned char*, MessageHeader*> advance_send();
    unsigned char* advance_receive(const MessageHeader* header);

    std::tuple<int,int> get_chain_lengths();

    const unsigned char *get_current_dh_public() const; //testing!!
private:
    bool reversed;
    bool due_to_send_new_dh;
    unsigned char root_key[32];

    NewChain send_chain;
    NewChain receive_chain;

    // initiator -> fresh
    // recipient -> recipient signed prekey pair
    unsigned char local_dh_public[32];
    std::unique_ptr<SecureMemoryBuffer> local_dh_priv = SecureMemoryBuffer::create(32);

    // initiator -> receiver signed prekey
    // recipient -> initiator ephemeral
    unsigned char remote_dh_public[32];

    std::unordered_map<int, unsigned char*> skipped_keys;
    int prev_chain_length;

    //methods
    void set_up_initial_state_for_initiator(const unsigned char* recipient_signed_public);
    void set_up_initial_state_for_recipient(const unsigned char* initiator_ephemeral_public);
    void set_up_initial_chain_keys();
    void generate_new_local_dh_keypair();

    void dh_ratchet_step(bool received_new_dh);
    unsigned char* progress_receive_ratchet();
    std::tuple<unsigned char*, MessageHeader*> progress_sending_ratchet();

    // dh output of local dh private * remote dh public
    unsigned char* dh() const;

    //serialisation
    void serialise(std::ostream& os) const;

    void deserialise(std::istream &in);
    friend class DoubleRatchetTest_Serialisation_Test;
};



#endif //NEWRATCHET_H
