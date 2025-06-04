#include <sodium.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include "XChaCha20-Poly1305.h"
#include "../utils/ConversionUtils.h"
#include <cstring>
#include <algorithm>

std::string encrypt_filename(const std::string& filename, const unsigned char* key) {
    std::string base_filename = std::filesystem::path(filename).filename().string();
    
    std::vector<unsigned char> cipher(base_filename.size() + crypto_aead_chacha20poly1305_IETF_ABYTES);
    unsigned long long cipher_len;
    
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);
    
    crypto_aead_chacha20poly1305_ietf_encrypt(
        cipher.data(), &cipher_len,
        reinterpret_cast<const unsigned char*>(base_filename.data()), base_filename.size(),
        nullptr, 0, nullptr, nonce, key);
    
    std::vector<unsigned char> result(sizeof(nonce) + cipher_len);
    std::copy_n(nonce, sizeof(nonce), result.begin());
    std::copy_n(cipher.data(), cipher_len, result.begin() + sizeof(nonce));
    
    std::string encrypted_name;
    for (unsigned char byte : result) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", byte);
        encrypted_name += hex;
    }
    
    return encrypted_name;
}

std::string decrypt_filename(const std::string& encrypted_name, const unsigned char* key) {
    std::vector<unsigned char> binary_data = hex_string_to_binary(encrypted_name);
    if (binary_data.empty()) {
        return "";
    }
    
    if (binary_data.size() < crypto_aead_chacha20poly1305_IETF_NPUBBYTES) {
        std::cerr << "Error: Binary data too small. Got " << binary_data.size() 
                  << " bytes, expected at least " << crypto_aead_chacha20poly1305_IETF_NPUBBYTES << " bytes" << std::endl;
        return "";
    }
    
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    std::copy_n(binary_data.begin(), sizeof(nonce), nonce);
    
    std::vector<unsigned char> cipher(binary_data.begin() + sizeof(nonce), binary_data.end());
    if (cipher.size() < crypto_aead_chacha20poly1305_IETF_ABYTES) {
        std::cerr << "Error: Cipher data too small. Got " << cipher.size() 
                  << " bytes, expected at least " << crypto_aead_chacha20poly1305_IETF_ABYTES << " bytes" << std::endl;
        return "";
    }
    
    std::vector<unsigned char> plain(cipher.size() - crypto_aead_chacha20poly1305_IETF_ABYTES);
    
    unsigned long long plain_len;
    int result = crypto_aead_chacha20poly1305_ietf_decrypt(
            plain.data(), &plain_len,
            nullptr,
            cipher.data(), cipher.size(),
            nullptr, 0,
            nonce, key);
            
    if (result != 0) {
        std::cerr << "Decryption failed with error code: " << result << std::endl;
        std::cerr << "Nonce size: " << sizeof(nonce) << ", Cipher size: " << cipher.size() << std::endl;
        return "";
    }
    
    return {reinterpret_cast<char*>(plain.data()), plain_len};
}

bool encrypt_file_and_name(const std::string& input_path, const std::string& output_dir, 
                           const unsigned char* key) {
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) {
        std::cerr << "Error: Could not open input file." << std::endl;
        return false;
    }
    
    std::string encrypted_filename = encrypt_filename(input_path, key);
    std::string output_path = std::filesystem::path(output_dir) / encrypted_filename;
    
    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file) {
        std::cerr << "Error: Could not open output file." << std::endl;
        return false;
    }

    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);

    output_file.write(reinterpret_cast<char*>(nonce), sizeof nonce);

    constexpr size_t CHUNK_SIZE = 4096;
    std::vector<unsigned char> buffer(CHUNK_SIZE);
    std::vector<unsigned char> cipher_buffer(CHUNK_SIZE + crypto_aead_chacha20poly1305_IETF_ABYTES);

    while (input_file) {
        input_file.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
        size_t bytes_read = input_file.gcount();
        
        if (bytes_read == 0) break;

        if (bytes_read < CHUNK_SIZE) {
            buffer.resize(bytes_read);
        }

        unsigned long long cipher_len;
        crypto_aead_chacha20poly1305_ietf_encrypt(
            cipher_buffer.data(), &cipher_len,
            buffer.data(), bytes_read,
            nullptr, 0, nullptr, nonce, key);

        auto chunk_size = static_cast<uint32_t>(cipher_len);
        output_file.write(reinterpret_cast<char*>(&chunk_size), sizeof(chunk_size));
        // TODO: Fix this
        output_file.write(reinterpret_cast<char*>(cipher_buffer.data()), cipher_len);
        
        sodium_increment(nonce, sizeof nonce);
    }

    return true;
}

bool decrypt_file_and_name(const std::string& encrypted_path, const std::string& output_dir, 
                           const unsigned char* key) {
    std::ifstream input_file(encrypted_path, std::ios::binary);
    if (!input_file) {
        std::cerr << "Error: Could not open encrypted file." << std::endl;
        return false;
    }
    
    std::string encrypted_filename = std::filesystem::path(encrypted_path).filename().string();
    std::string original_filename = decrypt_filename(encrypted_filename, key);
    
    if (original_filename.empty()) {
        std::cerr << "Error: Could not decrypt filename." << std::endl;
        return false;
    }
    
    std::string output_path = std::filesystem::path(output_dir) / original_filename;
    
    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file) {
        std::cerr << "Error: Could not open output file." << std::endl;
        return false;
    }

    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    input_file.read(reinterpret_cast<char*>(nonce), sizeof nonce);
    if (input_file.gcount() != sizeof nonce) {
        std::cerr << "Error: Input file is too short or corrupt." << std::endl;
        return false;
    }

    constexpr size_t MAX_CHUNK_SIZE = 4096 + crypto_aead_chacha20poly1305_IETF_ABYTES;
    std::vector<unsigned char> cipher_buffer(MAX_CHUNK_SIZE);
    std::vector<unsigned char> plain_buffer(MAX_CHUNK_SIZE);

    while (input_file) {
        uint32_t chunk_size;
        input_file.read(reinterpret_cast<char*>(&chunk_size), sizeof(chunk_size));
        if (input_file.gcount() != sizeof(chunk_size)) break;

        if (chunk_size > MAX_CHUNK_SIZE) {
            std::cerr << "Error: Invalid chunk size." << std::endl;
            return false;
        }

        input_file.read(reinterpret_cast<char*>(cipher_buffer.data()), chunk_size);
        if (input_file.gcount() != chunk_size) {
            std::cerr << "Error: Unexpected end of file." << std::endl;
            return false;
        }

        unsigned long long plain_len;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
                plain_buffer.data(), &plain_len,
                nullptr,
                cipher_buffer.data(), chunk_size,
                nullptr, 0,
                nonce, key) != 0) {
            std::cerr << "Error: Decryption failed. The file may be corrupted or tampered with." << std::endl;
            return false;
        }

        // TODO
        output_file.write(reinterpret_cast<char*>(plain_buffer.data()), plain_len);
        
        sodium_increment(nonce, sizeof nonce);
    }

    return true;
}

bool generate_encryption_key(unsigned char* key) {
    if (key == nullptr || sodium_init() < 0) {
        return false;
    }
    
    crypto_aead_chacha20poly1305_ietf_keygen(key);
    return true;
}

std::string encrypt_file_auto_key(const std::string& input_path, const std::string& output_dir) {
    
    if (input_path.empty() || output_dir.empty() || 
        !std::filesystem::exists(input_path) || 
        !std::filesystem::exists(output_dir) ||
        sodium_init() < 0) {
        return "";
    }
    
    // Generate a new key
    unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
    if (!generate_encryption_key(key)) {
        return "";
    }

    if (!encrypt_file_and_name(input_path, output_dir, key)) {
        return "";
    }
    
    // Return the key as hex string
    return bin_to_hex(key, sizeof(key));
}

bool decrypt_file_with_hex_key(const std::string& encrypted_path, const std::string& output_dir, 
                              const std::string& hex_key) {
    // validation
    if (encrypted_path.empty() || output_dir.empty() || hex_key.empty() ||
        !std::filesystem::exists(encrypted_path) || 
        !std::filesystem::exists(output_dir) ||
        sodium_init() < 0) {
        return false;
    }
    
    unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
    if (!hex_to_bin(hex_key, key, sizeof(key))) {
        return false;
    }
    
    return decrypt_file_and_name(encrypted_path, output_dir, key);
}

// Takes in binary key and message directly
std::vector<unsigned char> encrypt_message_given_key(const unsigned char* message, const size_t message_len, const unsigned char* key) {
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);

    std::vector<unsigned char> ciphertext(message_len + crypto_aead_chacha20poly1305_IETF_ABYTES);
    unsigned long long ciphertext_len;

    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_len,
        message, message_len,
        nullptr, 0, nullptr, nonce, key);

    std::vector<unsigned char> result(sizeof(nonce) + ciphertext_len);
    std::copy_n(nonce, sizeof(nonce), result.begin());
    std::copy_n(ciphertext.data(), ciphertext_len, result.begin() + sizeof(nonce));

    return result;
}

// Takes in binary key and encrypted data directly
std::vector<unsigned char> decrypt_message_given_key(const unsigned char* encrypted_data, size_t encrypted_len, const unsigned char* key) {
    if (encrypted_len < crypto_aead_chacha20poly1305_IETF_NPUBBYTES) {
        throw std::runtime_error("encrypted message (incl nonce) is too short");
    }

    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    std::copy_n(encrypted_data, sizeof(nonce), nonce);

    const unsigned char* ciphertext = encrypted_data + sizeof(nonce);
    size_t ciphertext_len = encrypted_len - sizeof(nonce);
    
    if (ciphertext_len < crypto_aead_chacha20poly1305_IETF_ABYTES) {
        throw std::runtime_error("ciphertext message is too short");
    }

    std::vector<unsigned char> plaintext(ciphertext_len - crypto_aead_chacha20poly1305_IETF_ABYTES);
    unsigned long long plaintext_len;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            ciphertext, ciphertext_len,
            nullptr, 0,
            nonce, key) != 0) {
        throw std::runtime_error("decryption failed");;
    }

    plaintext.resize(plaintext_len);
    return plaintext;
}
