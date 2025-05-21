#ifndef DOUBLERATCHET_H
#define DOUBLERATCHET_H

#include <cstring>
#include <sodium.h>
#include <stdexcept>
#include <iostream>
#include <string>

std::string bin2hex(const unsigned char* bin, size_t len);

class DoubleRatchet {
public:
    DoubleRatchet(const unsigned char* x3dh_root_key,
                  const unsigned char* remote_public_signed_prekey,
                  const unsigned char* local_public_ephemeral,
                  const unsigned char* local_private_ephemeral);

    unsigned char* message_send();

    unsigned char* message_receive(const unsigned char* new_remote_public_key);

    const unsigned char* get_public_key() const;

    void print_state() const;

private:
    unsigned char root_key[crypto_kdf_KEYBYTES];

    unsigned char send_key[crypto_kdf_KEYBYTES];
    unsigned char recv_key[crypto_kdf_KEYBYTES];

    unsigned char local_dh_public[crypto_kx_PUBLICKEYBYTES];
    unsigned char local_dh_private[crypto_kx_SECRETKEYBYTES];

    unsigned char remote_dh_public[crypto_kx_PUBLICKEYBYTES];
};

#endif //DOUBLERATCHET_H
