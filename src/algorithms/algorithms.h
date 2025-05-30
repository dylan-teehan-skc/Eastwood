//
// Created by Fred Sheppard on 22/05/2025.
//

#ifndef ALGORITHMS_H
#define ALGORITHMS_H
#include "constants.h"
#include <sodium.h>
#include "src/keys/secure_memory_buffer.h"
#include <memory>
#include <QByteArray>
#include <vector>

std::unique_ptr<SecureMemoryBuffer> derive_master_key(
    const std::unique_ptr<const std::string> &master_password,
    unsigned char salt[crypto_pwhash_SALTBYTES]
);

std::unique_ptr<SecureMemoryBuffer> encrypt_kek(
    const std::unique_ptr<SecureMemoryBuffer> &kek,
    unsigned char nonce[CHA_CHA_NONCE_LEN],
    const std::unique_ptr<SecureMemoryBuffer> &master_key
);

std::unique_ptr<SecureMemoryBuffer> decrypt_kek(
    unsigned char encrypted_kek[ENC_SYM_KEY_LEN],
    unsigned char nonce[CHA_CHA_NONCE_LEN],
    const std::unique_ptr<SecureMemoryBuffer> &master_key
);

std::unique_ptr<SecureMemoryBuffer> encrypt_symmetric_key(
    const std::unique_ptr<SecureMemoryBuffer> &sk,
    unsigned char nonce[CHA_CHA_NONCE_LEN]
);

std::unique_ptr<SecureMemoryBuffer> decrypt_symmetric_key(
    const unsigned char encrypted_key[ENC_SYM_KEY_LEN],
    const unsigned char nonce[CHA_CHA_NONCE_LEN]
);

std::unique_ptr<SecureMemoryBuffer> decrypt_symmetric_key(
    const QByteArray &encrypted_key,
    const QByteArray &nonce
);


std::unique_ptr<SecureMemoryBuffer> encrypt_secret_key(
    const std::unique_ptr<SecureMemoryBuffer> &sk,
    unsigned char nonce[CHA_CHA_NONCE_LEN]
);

std::unique_ptr<SecureMemoryBuffer> decrypt_secret_key(
    const unsigned char encrypted_sk[crypto_sign_SECRETKEYBYTES + ENC_OVERHEAD],
    const unsigned char nonce[CHA_CHA_NONCE_LEN]
);

std::unique_ptr<SecureMemoryBuffer> decrypt_secret_key(
    const QByteArray &encrypted_sk,
    const QByteArray &nonce
);

std::tuple<unsigned char*, std::unique_ptr<SecureMemoryBuffer>> generate_signed_prekey();

std::vector<std::tuple<unsigned char*, std::unique_ptr<SecureMemoryBuffer>, unsigned char*>> generate_onetime_keys(int num);

unsigned char* generate_unique_id_pair(std::string *input_one, std::string *input_two);


std::vector<unsigned char> encrypt_bytes(
    const QByteArray &data,
    const std::unique_ptr<SecureMemoryBuffer> &key,
    const unsigned char nonce[CHA_CHA_NONCE_LEN]
);

std::vector<unsigned char> decrypt_bytes(
    const QByteArray &encrypted_bytes,
    const std::unique_ptr<SecureMemoryBuffer> &key,
    const std::vector<unsigned char> &nonce
);

#endif //ALGORITHMS_H
