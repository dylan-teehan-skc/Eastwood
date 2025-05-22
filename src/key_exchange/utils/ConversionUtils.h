#ifndef CONVERSION_UTILS_H
#define CONVERSION_UTILS_H

#include <string>
#include <stdexcept>

bool hex_to_bin(const std::string& hex, unsigned char* bin, size_t bin_size);
std::string bin_to_hex(const unsigned char* bin, size_t bin_size);
std::vector<unsigned char> hex_string_to_binary(const std::string& hex_string);

#endif // CONVERSION_UTILS_H