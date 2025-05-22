#include <string>
#include <stdexcept>
#include <iostream>
#include <vector>

bool hex_to_bin(const std::string& hex, unsigned char* bin, size_t bin_size) {
    if (hex.length() != bin_size * 2) return false;
    
    for (size_t i = 0; i < bin_size; i++) {
        std::string byte = hex.substr(i * 2, 2);
        try {
            bin[i] = static_cast<unsigned char>(std::stoi(byte, nullptr, 16));
        } catch (const std::exception&) {
            return false;
        }
    }
    return true;
}

std::string bin_to_hex(const unsigned char* bin, size_t bin_size) {
    std::string result;
    char hex[3];
    
    for (size_t i = 0; i < bin_size; i++) {
        snprintf(hex, sizeof(hex), "%02x", bin[i]);
        result += hex;
    }
    
    return result;
}

std::vector<unsigned char> hex_string_to_binary(const std::string& hex_string) {
    std::vector<unsigned char> binary_data;
    
    if (hex_string.length() % 2 != 0) {
        std::cerr << "Error: Odd number of hex characters" << std::endl;
        return binary_data; // Return empty vector on error
    }
    
    for (size_t i = 0; i < hex_string.length(); i += 2) {
        std::string byte_string = hex_string.substr(i, 2);
        try {
            unsigned char byte = static_cast<unsigned char>(std::stoi(byte_string, nullptr, 16));
            binary_data.push_back(byte);
        } catch (const std::exception& e) {
            std::cerr << "Error converting hex to binary at position " << i << ": " << e.what() << std::endl;
            std::cerr << "Hex string: '" << byte_string << "'" << std::endl;
            return std::vector<unsigned char>(); // Return empty vector on error
        }
    }
    
    return binary_data;
}