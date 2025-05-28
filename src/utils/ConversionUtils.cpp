#include <string>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <fstream>
#include <filesystem>
#include <qbytearray.h>
#include <vector>

bool hex_to_bin(const std::string &hex, unsigned char *bin, size_t bin_size) {
    if (hex.length() != bin_size * 2) return false;

    for (size_t i = 0; i < bin_size; i++) {
        std::string byte = hex.substr(i * 2, 2);
        try {
            bin[i] = static_cast<unsigned char>(std::stoi(byte, nullptr, 16));
        } catch (const std::exception &) {
            return false;
        }
    }
    return true;
}

std::string bin_to_hex(const unsigned char *bin, size_t bin_size) {
    std::string result;
    char hex[3];

    for (size_t i = 0; i < bin_size; i++) {
        snprintf(hex, sizeof(hex), "%02x", bin[i]);
        result += hex;
    }

    return result;
}

std::vector<unsigned char> hex_string_to_binary(const std::string &hex_string) {
    std::vector<unsigned char> binary_data;

    if (hex_string.length() % 2 != 0) {
        std::cerr << "Error: Odd number of hex characters" << std::endl;
        return binary_data; // Return empty vector on error
    }

    for (size_t i = 0; i < hex_string.length(); i += 2) {
        std::string byte_string = hex_string.substr(i, 2);
        try {
            unsigned char byte = static_cast<unsigned char>(std::stoi(byte_string, nullptr, 16));
            binary_data.push_back(byte);
        } catch (const std::exception &e) {
            std::cerr << "Error converting hex to binary at position " << i << ": " << e.what() << std::endl;
            std::cerr << "Hex string: '" << byte_string << "'" << std::endl;
            return std::vector<unsigned char>(); // Return empty vector on error
        }
    }

    return binary_data;
}

std::string load_env_variable(const std::string &key, const std::string &default_value) {
    namespace fs = std::filesystem;

    fs::path exe_path = fs::current_path();
    fs::path current = exe_path;
    fs::path env_path;
    bool found = false;
    while (current != current.parent_path()) {
        if (fs::exists(current / "src")) {
            if (fs::exists(current / "src" / ".env")) {
                env_path = current / "src" / ".env";
                found = true;
                break;
            } else if (fs::exists(current / ".env")) {
                env_path = current / ".env";
                found = true;
                break;
            }
        }
        current = current.parent_path();
    }

    if (!found) {
        std::cerr << "Warning: Could not find .env file by searching up from: " << exe_path << std::endl;
        return default_value;
    }

    std::ifstream env_file(env_path);
    if (!env_file.is_open()) {
        std::cerr << "Warning: Could not open .env file at: " << env_path << std::endl;
        return default_value;
    }

    std::string line;
    while (std::getline(env_file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;

        // Find the position of the equals sign
        size_t pos = line.find('=');
        if (pos == std::string::npos) continue;

        // Extract key and value
        std::string current_key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);

        // Trim whitespace
        current_key.erase(0, current_key.find_first_not_of(" \t"));
        current_key.erase(current_key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);

        if (current_key == key) {
            return value;
        }
    }

    return default_value;
}

const unsigned char *q_byte_array_to_chars(const QByteArray &qb) {
    return reinterpret_cast<const unsigned char *>(qb.constData());
}

