#pragma once
#include <cstddef>
#include <memory>

class SecureMemoryBuffer {
public:
    static std::unique_ptr<SecureMemoryBuffer> create(size_t size);
    ~SecureMemoryBuffer();

    unsigned char* data() const;
    size_t size() const;

    // Non-copyable, movable
    SecureMemoryBuffer(const SecureMemoryBuffer&) = delete;
    SecureMemoryBuffer& operator=(const SecureMemoryBuffer&) = delete;
    SecureMemoryBuffer(SecureMemoryBuffer&&) noexcept;
    SecureMemoryBuffer& operator=(SecureMemoryBuffer&&) noexcept;

private:
    SecureMemoryBuffer(size_t size);
    void zero_and_unlock();
    unsigned char* buffer_;
    size_t size_;
}; 