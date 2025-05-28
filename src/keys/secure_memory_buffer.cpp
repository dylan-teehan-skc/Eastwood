#include "secure_memory_buffer.h"
#include <sodium.h>
#include <cstring>
#include <stdexcept>

std::unique_ptr<SecureMemoryBuffer> SecureMemoryBuffer::create(size_t size) {
    return std::unique_ptr<SecureMemoryBuffer>(new SecureMemoryBuffer(size));
}

SecureMemoryBuffer::SecureMemoryBuffer(size_t size) : buffer_(nullptr), size_(size) {
    buffer_ = static_cast<unsigned char*>(sodium_malloc(size_));
    if (!buffer_) throw std::bad_alloc();
    if (sodium_mlock(buffer_, size_) != 0) {
        sodium_free(buffer_);
        throw std::runtime_error("mlock failed");
    }
    std::memset(buffer_, 0, size_);
}

SecureMemoryBuffer::~SecureMemoryBuffer() {
    zero_and_unlock();
}

void SecureMemoryBuffer::zero_and_unlock() {
    if (buffer_) {
        sodium_memzero(buffer_, size_);
        sodium_munlock(buffer_, size_);
        sodium_free(buffer_);
        buffer_ = nullptr;
        size_ = 0;
    }
}

unsigned char* SecureMemoryBuffer::data() const {
    return buffer_;
}

size_t SecureMemoryBuffer::size() const {
    return size_;
}

SecureMemoryBuffer::SecureMemoryBuffer(SecureMemoryBuffer&& other) noexcept : buffer_(other.buffer_), size_(other.size_) {
    other.buffer_ = nullptr;
    other.size_ = 0;
}

SecureMemoryBuffer& SecureMemoryBuffer::operator=(SecureMemoryBuffer&& other) noexcept {
    if (this != &other) {
        zero_and_unlock();
        buffer_ = other.buffer_;
        size_ = other.size_;
        other.buffer_ = nullptr;
        other.size_ = 0;
    }
    return *this;
} 