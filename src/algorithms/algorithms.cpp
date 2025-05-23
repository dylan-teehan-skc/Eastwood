#include "algorithms.h"

int derive_master_key(
    unsigned char master_key[MASTER_KEY_LEN],
    const char *master_password,
    const size_t password_len,
    unsigned char salt[crypto_pwhash_SALTBYTES]
) {
    return crypto_pwhash(
        master_key, MASTER_KEY_LEN,
        master_password, password_len,
        salt,
        crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
        crypto_pwhash_argon2id_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_ARGON2ID13
    );
}

void encrypt_kek(
    unsigned char encrypted_kek[KEK_LEN + ENC_OVERHEAD],
    unsigned char kek[KEK_LEN],
    unsigned char nonce[NONCE_LEN],
    unsigned char master_key[MASTER_KEY_LEN]
) {
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        encrypted_kek, nullptr,
        kek, KEK_LEN,
        nullptr, 0, // No associated data
        nullptr, // Always null for this algorithm
        nonce, master_key
    );
}

void encrypt_secret_key(
    unsigned char encrypted_sk[crypto_sign_SECRETKEYBYTES + ENC_OVERHEAD],
    unsigned char sk[crypto_sign_SECRETKEYBYTES],
    unsigned char nonce[NONCE_LEN],
    unsigned char master_key[MASTER_KEY_LEN]
) {
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        encrypted_sk, nullptr,
        sk, crypto_sign_SECRETKEYBYTES,
        nullptr, 0, // No associated data
        nullptr, // Always null for this algorithm
        nonce, master_key
    );
}

int decrypt_kek(
    unsigned char decrypted_kek[KEK_LEN],
    unsigned char encrypted_kek[KEK_LEN + ENC_OVERHEAD],
    unsigned char nonce[NONCE_LEN],
    unsigned char master_key[MASTER_KEY_LEN]
) {
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
        decrypted_kek, nullptr,
        nullptr, // Secret nonce is always null for this algorithm
        encrypted_kek, KEK_LEN + ENC_OVERHEAD,
        nullptr, 0, // No associated data
        nonce, master_key
    );
}

int decrypt_secret_key(
    unsigned char decrypted_sk[crypto_sign_SECRETKEYBYTES],
    const unsigned char encrypted_sk[crypto_sign_SECRETKEYBYTES + ENC_OVERHEAD],
    const unsigned char nonce[NONCE_LEN],
    const unsigned char *key
) {
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
        decrypted_sk, nullptr,
        nullptr, // Secret nonce is always null for this algorithm
        encrypted_sk, crypto_sign_SECRETKEYBYTES + ENC_OVERHEAD,
        nullptr, 0, // No associated data
        nonce, key
    );
}
