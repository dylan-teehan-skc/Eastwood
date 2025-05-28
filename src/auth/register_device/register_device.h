#ifndef REGISTER_DEVICE_H
#define REGISTER_DEVICE_H

#include <sodium.h>

void register_device(unsigned char pk_new_device[crypto_sign_PUBLICKEYBYTES]);
void register_first_device();

#endif //REGISTER_DEVICE_H
