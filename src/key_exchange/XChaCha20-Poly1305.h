#ifndef XCHACHA20_POLY1305_H
#define XCHACHA20_POLY1305_H

#include <string>
#include <vector>

// Utility functions
bool hex_to_bin(const std::string& hex, unsigned char* bin, size_t bin_size);
std::string bin_to_hex(const unsigned char* bin, size_t bin_size);

// Filename encryption/decryption
std::string encrypt_filename(const std::string& filename, const unsigned char* key);
std::string decrypt_filename(const std::string& encrypted_name, const unsigned char* key);

// File encryption/decryption
bool encrypt_file_and_name(const std::string& input_path, const std::string& output_dir, 
                           const unsigned char* key);
bool decrypt_file_and_name(const std::string& encrypted_path, const std::string& output_dir, 
                           const unsigned char* key);

bool generate_encryption_key(unsigned char* key);
std::string encrypt_file_auto_key(const std::string& input_path, const std::string& output_dir);
bool decrypt_file_with_hex_key(const std::string& encrypted_path, const std::string& output_dir, 
                              const std::string& hex_key);

// Takes in binary key and message directly
std::vector<unsigned char> encrypt_message_given_key(const unsigned char* message, size_t message_len, const unsigned char* key);

// Takes in binary key and encrypted data directly
std::vector<unsigned char> decrypt_message_given_key(const unsigned char* encrypted_data, size_t encrypted_len, const unsigned char* key);

#endif // XCHACHA20_POLY1305_H 