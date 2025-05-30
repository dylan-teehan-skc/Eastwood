#ifndef EASTWOOD_IDENTITY_SESSION_ID_H
#define EASTWOOD_IDENTITY_SESSION_ID_H

#include <array>
#include <cstring>
#include "sodium.h"

struct IdentitySessionId {
    std::array<unsigned char, crypto_hash_sha256_BYTES> data;
    
    bool operator<(const IdentitySessionId& other) const {
        return memcmp(data.data(), other.data.data(), crypto_hash_sha256_BYTES) < 0;
    }
    
    bool operator==(const IdentitySessionId& other) const {
        return memcmp(data.data(), other.data.data(), crypto_hash_sha256_BYTES) == 0;
    }
};

#endif //EASTWOOD_IDENTITY_SESSION_ID_H 