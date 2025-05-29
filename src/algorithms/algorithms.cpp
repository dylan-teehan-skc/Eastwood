#include "algorithms.h"

#include <tuple>

#include "src/keys/kek_manager.h"
#include "src/key_exchange/utils.h"
#include "src/sql/queries.h"
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

std::tuple<unsigned char*, std::unique_ptr<SecureMemoryBuffer>> generate_signed_prekey() {
    auto *pk = new unsigned char[crypto_box_PUBLICKEYBYTES];
    auto sk_buffer = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);

    crypto_box_keypair(pk, sk_buffer->data());

    // Generate nonce for encryption
    auto *nonce = new unsigned char[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce, CHA_CHA_NONCE_LEN);

    // Encrypt and save the signed prekey pair
    const auto encrypted_sk = encrypt_secret_key(sk_buffer, nonce);
    save_encrypted_keypair("signed", pk, encrypted_sk, nonce);

    auto decrypted_device_key = get_decrypted_sk("device");

    return std::make_tuple(pk, std::move(sk_buffer));
}

std::vector<std::tuple<unsigned char*, std::unique_ptr<SecureMemoryBuffer>, unsigned char*>> generate_onetime_keys(int num) {
    std::vector<std::tuple<unsigned char*, std::unique_ptr<SecureMemoryBuffer>, unsigned char*>> keys;
    for (int i = 0; i < num; i++) {
        auto *pk = new unsigned char[crypto_box_PUBLICKEYBYTES];
        auto sk_buffer = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
        crypto_box_keypair(pk, sk_buffer->data());

        auto *nonce = new unsigned char[CHA_CHA_NONCE_LEN];
        randombytes_buf(nonce, CHA_CHA_NONCE_LEN);

        std::unique_ptr<SecureMemoryBuffer> encrypted_onetime_sk = encrypt_secret_key(sk_buffer, nonce);
        keys.push_back(std::make_tuple(pk, std::move(encrypted_onetime_sk), nonce));
    }

    save_encrypted_onetime_keys(keys);
    return keys;
}
