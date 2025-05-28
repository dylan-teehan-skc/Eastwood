#ifndef CONSTANTS_H
#define CONSTANTS_H


#define MASTER_KEY_LEN 32
#define ENC_OVERHEAD crypto_aead_xchacha20poly1305_ietf_ABYTES
#define SYM_KEY_LEN crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define ENC_SYM_KEY_LEN crypto_secretbox_KEYBYTES + ENC_OVERHEAD
#define ENC_SECRET_KEY_LEN crypto_sign_SECRETKEYBYTES + ENC_OVERHEAD
#define CHA_CHA_NONCE_LEN crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#endif //CONSTANTS_H
