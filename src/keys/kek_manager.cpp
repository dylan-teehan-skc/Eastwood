#include "kek_manager.h"

#include <memory>

// Initialize static members
std::unique_ptr<KEKWrapper> KEKManager::kek_wrapper = nullptr;
bool KEKManager::is_initialized = false; 