//
// Created by niall on 04/06/25.
//

#ifndef URLENCODER_H
#define URLENCODER_H

#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <cctype>

inline std::string URLEncode(std::string& url) {
    std::ostringstream encoded;
    for (unsigned char x: url) {
         if(isalnum(x) || x=='-' || x == '_' || x == '.' || x == '~') {
             encoded << x;
         }else{
           encoded << '%' << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << std::hex << (int)x;
         }
    }
    return encoded.str();
}
inline std::string URLDecode(std::string& url) {
    std::ostringstream decoded;
    for (size_t i = 0; i < url.length(); ++i){
        if(url[i] == '%' && i+2 < url.length()) {
            std::string hex = url.substr(i+1,2);
            decoded << static_cast<char>(std::stoi(hex, nullptr, 16));
            i+=2;
        }else if (url[i] == '+') {
            decoded << ' ';
        } else {
            decoded << url[i];
        }
    }
    return decoded.str();
}


#endif //URLENCODER_H
