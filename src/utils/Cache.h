#pragma once

#include <unordered_map>
#include <string>
#include <optional>
#include <chrono>

template<typename T>
class Cache {
private:
    struct CacheEntry {
        T data;
        std::chrono::system_clock::time_point expiry;
    };

    std::unordered_map<std::string, CacheEntry> cache;
    std::chrono::seconds default_ttl;

public:
    explicit Cache(std::chrono::seconds ttl = std::chrono::seconds(300)) 
        : default_ttl(ttl) {}

    void set(const std::string& key, const T& value, 
             std::chrono::seconds ttl = std::chrono::seconds(0)) {
        auto expiry = std::chrono::system_clock::now() + 
                     (ttl.count() > 0 ? ttl : default_ttl);
        cache[key] = {value, expiry};
    }

    std::optional<T> get(const std::string& key) {
        auto it = cache.find(key);
        if (it == cache.end()) {
            return std::nullopt;
        }

        if (std::chrono::system_clock::now() > it->second.expiry) {
            cache.erase(it);
            return std::nullopt;
        }

        return it->second.data;
    }

    void remove(const std::string& key) {
        cache.erase(key);
    }

    void clear() {
        cache.clear();
    }

    bool exists(const std::string& key) {
        auto it = cache.find(key);
        if (it == cache.end()) {
            return false;
        }

        if (std::chrono::system_clock::now() > it->second.expiry) {
            cache.erase(it);
            return false;
        }

        return true;
    }
};
