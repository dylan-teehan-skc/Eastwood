#include "algorithms.h"

#include <QIODevice>
#include <tuple>
#include <unistd.h>

#include "src/keys/kek_manager.h"
#include "src/key_exchange/utils.h"
#include "src/sql/queries.h"
#include "src/utils/ConversionUtils.h"

std::unique_ptr<SecureMemoryBuffer> derive_master_key(
    std::unique_ptr<SecureMemoryBuffer>&& master_password,
    unsigned char salt[crypto_pwhash_SALTBYTES]
) {
    auto master_key = SecureMemoryBuffer::create(MASTER_KEY_LEN);
    if (crypto_pwhash(
            master_key->data(), master_key->size(),
            reinterpret_cast<const char*>(master_password->data()), master_password->size(),
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

std::unique_ptr<SecureMemoryBuffer> decrypt_kek(
    QByteArray &encrypted_kek,
    QByteArray &nonce,
    const std::unique_ptr<SecureMemoryBuffer> &master_key
) {
    return decrypt_kek(
        reinterpret_cast<unsigned char *>(encrypted_kek.data()),
        reinterpret_cast<unsigned char *>(nonce.data()),
        master_key
    );
}

std::unique_ptr<SecureMemoryBuffer> encrypt_symmetric_key(
    const std::unique_ptr<SecureMemoryBuffer> &sk,
    unsigned char nonce[CHA_CHA_NONCE_LEN]
) {
    auto buf = SecureMemoryBuffer::create(ENC_SYM_KEY_LEN);
    const auto kek = KekManager::instance().getKEK();
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            buf->data(), nullptr,
            sk->data(), SYM_KEY_LEN,
            nullptr, 0, // No associated data
            nullptr, // Always null for this algorithm
            nonce, kek->data()
        ) != 0) {
        throw std::runtime_error("Failed to encrypt symmetric key");
    }
    return buf;
}

std::unique_ptr<SecureMemoryBuffer> decrypt_symmetric_key(
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

std::unique_ptr<SecureMemoryBuffer> decrypt_symmetric_key(
    const QByteArray &encrypted_key,
    const QByteArray &nonce
) {
    return decrypt_symmetric_key(q_byte_array_to_chars(encrypted_key), q_byte_array_to_chars(nonce));
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

std::tuple<unsigned char *, std::unique_ptr<SecureMemoryBuffer> > generate_signed_prekey() {
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

std::vector<std::tuple<unsigned char *, std::unique_ptr<SecureMemoryBuffer>, unsigned char *> >
generate_onetime_keys(int num) {
    std::vector<std::tuple<unsigned char *, std::unique_ptr<SecureMemoryBuffer>, unsigned char *> > keys;
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

unsigned char *generate_unique_id_pair(std::string *input_one, std::string *input_two) {
    size_t out_size = crypto_hash_sha256_BYTES;
    auto hashed_one = new unsigned char[out_size];
    auto hashed_two = new unsigned char[out_size];

    // Generate initial hashes
    crypto_hash_sha256(hashed_one, reinterpret_cast<const unsigned char *>(input_one->c_str()), input_one->length());
    crypto_hash_sha256(hashed_two, reinterpret_cast<const unsigned char *>(input_two->c_str()), input_two->length());

    unsigned char concatenated[64];

    if (memcmp(hashed_one, hashed_two, 32) <= 0) {
        memcpy(concatenated, hashed_one, 32);
        memcpy(concatenated + 32, hashed_two, 32);
    } else {
        memcpy(concatenated, hashed_two, 32);
        memcpy(concatenated + 32, hashed_one, 32);
    }

    auto result = new unsigned char[crypto_hash_sha256_BYTES];
    // Hash the concatenated result into hashed_one
    crypto_hash_sha256(result, concatenated, 64); // Use full 64-byte concatenated array

    // Clean up hashed_two since we don't need it anymore
    delete[] hashed_two;
    delete[] hashed_one;

    return result; // Caller is responsible for deleting this
}

std::vector<unsigned char> encrypt_message_given_key(const unsigned char* message, const size_t message_len, const unsigned char* key) {

    unsigned char nonce[crypto_aead_xchacha20poly1305_IETF_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<unsigned char> ciphertext(message_len + crypto_aead_xchacha20poly1305_IETF_ABYTES);
    unsigned long long ciphertext_len;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            message, message_len,
            nullptr, 0, // No associated data
            nullptr, // Always null for this algorithm
            nonce, key
        ) != 0) {
        throw std::runtime_error("Failed to encrypt message");
    }

    std::vector<unsigned char> result(sizeof(nonce) + ciphertext_len);
    std::copy_n(nonce, sizeof(nonce), result.begin());
    std::copy_n(ciphertext.data(), ciphertext_len, result.begin() + sizeof(nonce));

    return result;
}

std::vector<unsigned char> decrypt_message_given_key(const unsigned char* encrypted_data, size_t encrypted_len, const unsigned char* key) {
    if (encrypted_len < crypto_aead_xchacha20poly1305_IETF_NPUBBYTES) {
        throw std::runtime_error("encrypted message (incl nonce) is too short");
    }

    unsigned char nonce[crypto_aead_xchacha20poly1305_IETF_NPUBBYTES];
    std::copy_n(encrypted_data, sizeof(nonce), nonce);

    const unsigned char* ciphertext = encrypted_data + sizeof(nonce);
    size_t ciphertext_len = encrypted_len - sizeof(nonce);
    
    if (ciphertext_len < crypto_aead_xchacha20poly1305_IETF_ABYTES) {
        throw std::runtime_error("ciphertext message is too short");
    }

    std::vector<unsigned char> plaintext(ciphertext_len - crypto_aead_xchacha20poly1305_IETF_ABYTES);
    unsigned long long plaintext_len;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr, // Secret nonce is always null for this algorithm
            ciphertext, ciphertext_len,
            nullptr, 0, // No associated data
            nonce, key
        ) != 0) {
        throw std::runtime_error("Failed to decrypt message: authentication failed or corrupted data");
    }

    plaintext.resize(plaintext_len);
    return plaintext;
}

std::vector<unsigned char> encrypt_message_with_nonce(
    const QByteArray &data,
    const std::unique_ptr<SecureMemoryBuffer> &key,
    const unsigned char nonce[CHA_CHA_NONCE_LEN]
) {
    const auto encrypted_len = data.size() + ENC_OVERHEAD;
    std::vector<unsigned char> encrypted_bytes;
    encrypted_bytes.resize(encrypted_len);

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            encrypted_bytes.data(), nullptr,
            reinterpret_cast<const unsigned char *>(data.constData()),
            data.size(),
            nullptr, 0, // No associated data
            nullptr, // Always null for this algorithm
            nonce, key->data()
        ) != 0) {
        throw std::runtime_error("Failed to encrypt file");
    }
    return encrypted_bytes;
}

std::vector<unsigned char> decrypt_message_with_nonce(
    const QByteArray &encrypted_bytes,
    const std::unique_ptr<SecureMemoryBuffer> &key,
    const std::vector<unsigned char> &nonce
) {
    std::vector<unsigned char> decrypted_bytes;
    decrypted_bytes.resize(encrypted_bytes.size());
    unsigned long long size_out = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted_bytes.data(), &size_out,
            nullptr, // Secret nonce is always null for this algorithm
            reinterpret_cast<const unsigned char *>(encrypted_bytes.constData()),
            encrypted_bytes.size(),
            nullptr, 0, // No associated data
            nonce.data(), key->data()
        ) != 0) {
        throw std::runtime_error("Failed to decrypt file");
    }
    decrypted_bytes.resize(size_out);
    return decrypted_bytes;
}
