#ifndef EASTWOOD_CRYPTO_UTILS_H
#define EASTWOOD_CRYPTO_UTILS_H

#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

// Convert binary data to a hexadecimal string
inline std::string bin2hex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

// Convert binary data to base64 string
inline std::string bin2base64(const unsigned char* data, size_t len) {
    static const char* base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string ret;
    ret.reserve(((len + 2) / 3) * 4);
    
    for (size_t i = 0; i < len; i += 3) {
        unsigned char octet_a = i < len ? data[i] : 0;
        unsigned char octet_b = i + 1 < len ? data[i + 1] : 0;
        unsigned char octet_c = i + 2 < len ? data[i + 2] : 0;
        
        unsigned char triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        
        ret.push_back(base64_chars[(triple >> 18) & 0x3F]);
        ret.push_back(base64_chars[(triple >> 12) & 0x3F]);
        ret.push_back(base64_chars[(triple >> 6) & 0x3F]);
        ret.push_back(base64_chars[triple & 0x3F]);
    }
    
    // Add padding
    switch (len % 3) {
        case 1:
            ret[ret.size() - 2] = '=';
            ret[ret.size() - 1] = '=';
            break;
        case 2:
            ret[ret.size() - 1] = '=';
            break;
    }
    
    return ret;
}

// Convert base64 string to binary data
inline std::vector<unsigned char> base642bin(const std::string& base64_str) {
    static const unsigned char base64_lookup[] = {
        62, 255, 62, 255, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255,
        255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        255, 255, 255, 255, 63, 255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
        36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
    };
    
    std::vector<unsigned char> ret;
    ret.reserve(((base64_str.size() + 3) / 4) * 3);
    
    for (size_t i = 0; i < base64_str.size(); i += 4) {
        unsigned char sextet_a = base64_str[i] <= 'z' ? base64_lookup[base64_str[i] - 43] : 255;
        unsigned char sextet_b = i + 1 < base64_str.size() && base64_str[i + 1] <= 'z' ? 
            base64_lookup[base64_str[i + 1] - 43] : 255;
        unsigned char sextet_c = i + 2 < base64_str.size() && base64_str[i + 2] <= 'z' ? 
            base64_lookup[base64_str[i + 2] - 43] : 255;
        unsigned char sextet_d = i + 3 < base64_str.size() && base64_str[i + 3] <= 'z' ? 
            base64_lookup[base64_str[i + 3] - 43] : 255;
        
        if (sextet_a == 255 || sextet_b == 255) break;
        
        unsigned char triple = (sextet_a << 18) + (sextet_b << 12);
        
        if (sextet_c != 255) {
            triple += sextet_c << 6;
            if (sextet_d != 255) {
                triple += sextet_d;
                ret.push_back((triple >> 16) & 0xFF);
                ret.push_back((triple >> 8) & 0xFF);
                ret.push_back(triple & 0xFF);
            } else {
                ret.push_back((triple >> 16) & 0xFF);
                ret.push_back((triple >> 8) & 0xFF);
            }
        } else {
            ret.push_back((triple >> 16) & 0xFF);
        }
    }
    
    return ret;
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