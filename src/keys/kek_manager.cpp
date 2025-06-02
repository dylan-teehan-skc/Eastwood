#include "kek_manager.h"
#include <stdexcept>

KekManager& KekManager::instance() {
    static KekManager instance;
    return instance;
}

void KekManager::setKEK(std::unique_ptr<SecureMemoryBuffer> kek) {
    kek_ = std::move(kek);
}

SecureMemoryBuffer* KekManager::getKEK() const {
    if (!kek_) throw std::runtime_error("KEK not loaded");
    return kek_.get();
}

bool KekManager::isLoaded() const {
    return kek_ != nullptr;
}

void KekManager::unload() {
    kek_.reset();
}