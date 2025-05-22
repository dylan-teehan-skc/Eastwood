#ifndef EASTWOOD_CRYPTO_UTILS_H
#define EASTWOOD_CRYPTO_UTILS_H

#include <string>
#include <sstream>
#include <iomanip>

// Convert binary data to a hexadecimal string
inline std::string bin2hex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

#endif // EASTWOOD_CRYPTO_UTILS_H 