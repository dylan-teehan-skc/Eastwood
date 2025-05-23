#ifndef CONSTANTS_H
#define CONSTANTS_H


#define MASTER_KEY_LEN crypto_pwhash_argon2id_STRBYTES
#define KEK_LEN crypto_secretbox_KEYBYTES
#define NONCE_LEN crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define ENC_OVERHEAD crypto_aead_xchacha20poly1305_ietf_ABYTES

#endif //CONSTANTS_H
