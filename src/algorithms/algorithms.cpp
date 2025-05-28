#include "algorithms.h"

#include "src/keys/kek_manager.h"
#include "src/utils/ConversionUtils.h"

std::unique_ptr<SecureMemoryBuffer> derive_master_key(
    const std::unique_ptr<const std::string> &master_password,
    unsigned char salt[crypto_pwhash_SALTBYTES]
) {
    auto master_key = SecureMemoryBuffer::create(MASTER_KEY_LEN);
    if (crypto_pwhash(
            master_key->data(), master_key->size(),
            master_password->c_str(), master_password->length(),
            salt,
            crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
            crypto_pwhash_argon2id_MEMLIMIT_MODERATE,
            crypto_pwhash_ALG_ARGON2ID13
        ) != 0) {
        throw std::runtime_error("Failed to encrypt master key");
    };
    return master_key;
}

std::unique_ptr<SecureMemoryBuffer> encrypt_kek(
    const std::unique_ptr<SecureMemoryBuffer> &kek,
    unsigned char nonce[CHA_CHA_NONCE_LEN],
    const std::unique_ptr<SecureMemoryBuffer> &master_key
) {
    if (kek->size() != SYM_KEY_LEN) {
        throw std::runtime_error("Incorrect KEK size found during encryption");
    }
    auto encrypted_kek = SecureMemoryBuffer::create(ENC_SYM_KEY_LEN);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            encrypted_kek->data(), nullptr,
            kek->data(), kek->size(),
            nullptr, 0, // No associated data
            nullptr, // Always null for this algorithm
            nonce, master_key->data()
        ) != 0) {
        throw std::runtime_error("Failed to encrypt kek");
    };
    return encrypted_kek;
}

std::unique_ptr<SecureMemoryBuffer> decrypt_kek(
    unsigned char encrypted_kek[ENC_SYM_KEY_LEN],
    unsigned char nonce[CHA_CHA_NONCE_LEN],
    const std::unique_ptr<SecureMemoryBuffer> &master_key
) {
    auto kek = SecureMemoryBuffer::create(SYM_KEY_LEN);
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            kek->data(), nullptr,
            nullptr, // Secret nonce is always null for this algorithm
            encrypted_kek, ENC_SYM_KEY_LEN,
            nullptr, 0, // No associated data
            nonce, master_key->data()
        ) != 0) {
        throw std::runtime_error("Failed to decrypt kek");
    };
    return kek;
}

std::unique_ptr<SecureMemoryBuffer> decrypt_key(
    const unsigned char encrypted_key[ENC_SYM_KEY_LEN],
    const unsigned char nonce[CHA_CHA_NONCE_LEN]
) {
    const auto kek = KekManager::instance().getKEK();
    auto key = SecureMemoryBuffer::create(SYM_KEY_LEN);
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            key->data(), nullptr,
            nullptr, // Secret nonce is always null for this algorithm
            encrypted_key, ENC_SYM_KEY_LEN,
            nullptr, 0, // No associated data
            nonce, kek->data()
        ) != 0) {
        throw std::runtime_error("Failed to decrypt kek");
    };
    return key;
}

std::unique_ptr<SecureMemoryBuffer> decrypt_key(
    const QByteArray &encrypted_key,
    const QByteArray &nonce
) {
    return decrypt_key(q_byte_array_to_chars(encrypted_key), q_byte_array_to_chars(nonce));
}

std::unique_ptr<SecureMemoryBuffer> encrypt_secret_key(
    const std::unique_ptr<SecureMemoryBuffer> &sk,
    unsigned char nonce[CHA_CHA_NONCE_LEN]
) {
    auto buf = SecureMemoryBuffer::create(ENC_SECRET_KEY_LEN);
    const auto kek = KekManager::instance().getKEK();
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            buf->data(), nullptr,
            sk->data(), crypto_sign_SECRETKEYBYTES,
            nullptr, 0, // No associated data
            nullptr, // Always null for this algorithm
            nonce, kek->data()
        ) != 0) {
        throw std::runtime_error("Failed to encrypt secret key");
    }
    return buf;
}

std::unique_ptr<SecureMemoryBuffer> decrypt_secret_key(
    const unsigned char encrypted_sk[ENC_SECRET_KEY_LEN],
    const unsigned char nonce[CHA_CHA_NONCE_LEN]
) {
    auto buf = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
    const auto kek = KekManager::instance().getKEK();
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            buf->data(), nullptr,
            nullptr, // Secret nonce is always null for this algorithm
            encrypted_sk, ENC_SECRET_KEY_LEN,
            nullptr, 0, // No associated data
            nonce, kek->data()
        ) != 0) {
        throw std::runtime_error("Failed to decrypt secret key");
    }
    return buf;
}

std::unique_ptr<SecureMemoryBuffer> decrypt_secret_key(
    const QByteArray &encrypted_sk,
    const QByteArray &nonce
) {
    return decrypt_secret_key(q_byte_array_to_chars(encrypted_sk), q_byte_array_to_chars(nonce));
}
