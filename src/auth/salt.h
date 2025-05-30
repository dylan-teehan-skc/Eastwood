#ifndef SAVE_SALT_H
#define SAVE_SALT_H

#include <sodium.h>
#include <string>

void get_salt_from_file(const std::string &username, unsigned char salt[crypto_pwhash_SALTBYTES]);

void save_salt_to_file(const std::string &username, unsigned char salt[crypto_pwhash_SALTBYTES]);

#endif //SAVE_SALT_H
