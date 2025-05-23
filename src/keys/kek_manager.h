#ifndef EASTWOOD_KEK_MANAGER_H
#define EASTWOOD_KEK_MANAGER_H

#include <memory>
#include <sodium.h>
#include <sys/mman.h>
#include <stdexcept>

#include "../algorithms/constants.h"

inline int decrypt_kek(
    unsigned char decrypted_kek[KEK_LEN],
    unsigned char encrypted_kek[KEK_LEN + ENC_OVERHEAD],
    unsigned char nonce[NONCE_LEN],
    unsigned char master_key[MASTER_KEY_LEN]
) {
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
        decrypted_kek, nullptr,
        nullptr, // Secret nonce is always null for this algorithm
        encrypted_kek, KEK_LEN + ENC_OVERHEAD,
        nullptr, 0, // No associated data
        nonce, master_key
    );
}

// Secure memory allocation that prevents swapping to disk
class SecureMemory {
private:
    void *ptr;
    size_t size;

public:
    SecureMemory(size_t sz) : size(sz) {
        ptr = malloc(size);
        if (!ptr) throw std::bad_alloc();

        // Lock memory to prevent swapping to disk
        if (mlock(ptr, size) != 0) {
            free(ptr);
            throw std::runtime_error("Failed to lock memory");
        }

        // Zero the memory
        sodium_memzero(ptr, size);
    }

    ~SecureMemory() {
        if (ptr) {
            // Zero memory before freeing
            sodium_memzero(ptr, size);
            munlock(ptr, size);
            free(ptr);
        }
    }

    // Delete copy constructor and assignment
    SecureMemory(const SecureMemory &) = delete;

    SecureMemory &operator=(const SecureMemory &) = delete;

    // Allow move semantics
    SecureMemory(SecureMemory &&other) noexcept : ptr(other.ptr), size(other.size) {
        other.ptr = nullptr;
        other.size = 0;
    }

    SecureMemory &operator=(SecureMemory &&other) noexcept {
        if (this != &other) {
            if (ptr) {
                sodium_memzero(ptr, size);
                munlock(ptr, size);
                free(ptr);
            }
            ptr = other.ptr;
            size = other.size;
            other.ptr = nullptr;
            other.size = 0;
        }
        return *this;
    }

    void *get() { return ptr; }
    const void *get() const { return ptr; }
    size_t get_size() const { return size; }
};

// RAII wrapper for KEK
class KEKWrapper {
private:
    SecureMemory memory;
    bool is_loaded;

public:
    KEKWrapper() : memory(KEK_LEN), is_loaded(false) {
    }

    void load(
        unsigned char encrypted_kek[KEK_LEN + ENC_OVERHEAD],
        unsigned char nonce[NONCE_LEN],
        unsigned char master_key[MASTER_KEY_LEN]
    ) {
        if (is_loaded) {
            throw std::runtime_error("KEK already loaded");
        }

        if (decrypt_kek(
                static_cast<unsigned char *>(memory.get()),
                encrypted_kek,
                nonce,
                master_key) != 0) {
            throw std::runtime_error("Failed to decrypt KEK");
        }

        is_loaded = true;
    }

    const unsigned char *get() const {
        if (!is_loaded) {
            throw std::runtime_error("KEK not loaded");
        }
        return static_cast<const unsigned char *>(memory.get());
    }

    void unload() {
        if (is_loaded) {
            sodium_memzero(memory.get(), memory.get_size());
            is_loaded = false;
        }
    }

    ~KEKWrapper() {
        unload();
    }
};

// Singleton KEK manager
class KEKManager {
private:
    static std::unique_ptr<KEKWrapper> kek_wrapper;
    static bool is_initialized;

    KEKManager() = delete; // Prevent instantiation

public:
    static void initialize() {
        if (!is_initialized) {
            kek_wrapper = std::make_unique<KEKWrapper>();
            is_initialized = true;
        }
    }

    static void load_kek(
        unsigned char encrypted_kek[KEK_LEN + ENC_OVERHEAD],
        unsigned char nonce[NONCE_LEN],
        unsigned char master_key[MASTER_KEY_LEN]
    ) {
        if (!is_initialized) {
            throw std::runtime_error("KEKManager not initialized");
        }
        kek_wrapper->load(encrypted_kek, nonce, master_key);
    }

    static const unsigned char *get_kek() {
        if (!is_initialized) {
            throw std::runtime_error("KEKManager not initialized");
        }
        return kek_wrapper->get();
    }

    static void unload_kek() {
        if (is_initialized) {
            kek_wrapper->unload();
        }
    }

    static void cleanup() {
        kek_wrapper.reset();
        is_initialized = false;
    }
};

#endif // EASTWOOD_KEK_MANAGER_H
