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

inline unsigned char* concat_ordered(const unsigned char* a, size_t a_len,
                                     const unsigned char* b, size_t b_len,
                                     size_t& out_len) {
    // Compare a and b lexicographically
    int cmp = memcmp(a, b, std::min(a_len, b_len));
    if (cmp == 0) cmp = a_len - b_len;  // if equal up to min length, use size to decide

    const unsigned char* first = cmp <= 0 ? a : b;
    size_t first_len = cmp <= 0 ? a_len : b_len;

    const unsigned char* second = cmp <= 0 ? b : a;
    size_t second_len = cmp <= 0 ? b_len : a_len;

    out_len = first_len + second_len;
    unsigned char* result = new unsigned char[out_len];

    memcpy(result, first, first_len);
    memcpy(result + first_len, second, second_len);

    return result;
}


#endif // EASTWOOD_CRYPTO_UTILS_H 