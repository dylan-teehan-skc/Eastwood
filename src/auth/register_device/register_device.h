#ifndef REGISTER_DEVICE_H
#define REGISTER_DEVICE_H

#include <string>
#include <sodium.h>

void add_trusted_device(unsigned char pk_new_device[crypto_sign_PUBLICKEYBYTES], const std::string &device_name);
void register_first_device();

#endif //REGISTER_DEVICE_H
