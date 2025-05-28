#pragma once
#include <memory>
#include "secure_memory_buffer.h"

class KekManager {
public:
    static KekManager& instance();

    void setKEK(std::unique_ptr<SecureMemoryBuffer> kek);
    SecureMemoryBuffer* getKEK() const;
    bool isLoaded() const;

    // Non-copyable
    KekManager(const KekManager&) = delete;
    KekManager& operator=(const KekManager&) = delete;
private:
    KekManager() = default;
    std::unique_ptr<SecureMemoryBuffer> kek_;
}; 