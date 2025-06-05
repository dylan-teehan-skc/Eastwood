#include <gtest/gtest.h>
#include "src/keys/secure_memory_buffer.h"
#include "src/auth/login/login.h"
#include "src/auth/register_user/register_user.h"
#include "src/sql/queries.h"
#include "src/database/database.h"
#include "src/endpoints/endpoints.h"
#include <sodium.h>
#include <memory>
#include <stdexcept>
#include "ui/windows/login/login.h"
#include "./libraries/HTTPSClient.h"
#include <iostream>
#define SQLITE_HAS_CODEC 1
#include <fstream>
#include <random>
#include "auth/register_device/register_device.h"
#include "communication/send_file_to/send_file_to.h"
#include "communication/upload_file/upload_file.h"
#include "src/auth/rotate_master_key/rotate_master_key.h"
#include "auth/logout.h"

std::string generateRandomString(int length) {
    const std::string characters =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789";
    std::mt19937 generator(static_cast<unsigned int>(
        std::chrono::system_clock::now().time_since_epoch().count()
    ));
    std::uniform_int_distribution<> distribution(0, characters.length() - 1);
    std::string randomString;
    randomString.reserve(length);
    for (int i = 0; i < length; ++i) {
        randomString += characters[distribution(generator)];
    }
    return randomString;
}

int main() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Libsodium initialization failed");
    }

    const std::string username = generateRandomString(8);
    auto password = SecureMemoryBuffer::create(32);
    memcpy(password->data(), "password1234", 11);

    qDebug() << "Registering user";
    register_user(username, std::move(password));
    qDebug() << "Registering device";
    register_first_device();
    qDebug() << "Logging in";
    auto loginPassword = SecureMemoryBuffer::create(32);
    memcpy(loginPassword->data(), "password1234", 11);
    login_user(username, std::move(loginPassword), false);

    auto new_password = SecureMemoryBuffer::create(32);
    memcpy(new_password->data(), "even_stronger_password", 21);
    qDebug() << "Trying to rotate password without current master key";
    const auto fake_password = SecureMemoryBuffer::create(MASTER_KEY_LEN);
    randombytes_buf(fake_password->data(), MASTER_KEY_LEN);
    if (Database::get().verify_master_key(fake_password)) {
        throw std::logic_error("Random password used to rotate database key");
    };
    qDebug() << "Rotating password";
    auto currentPassword = SecureMemoryBuffer::create(32);
    memcpy(currentPassword->data(), "password1234", 11);
    rotate_master_password(username, std::move(currentPassword), std::move(new_password));
    qDebug() << "Posting keybundles";
    auto signed_prekey = generate_signed_prekey();
    post_new_keybundles(
        get_decrypted_keypair("device"),
        &signed_prekey,
        generate_onetime_keys(100)
    );
    qDebug() << "Getting devices";
    get_devices();
    qDebug() << "Logging out";
    logout();

    qDebug() << "Attempting to send authenticated request when logged out";
    try {
        get_devices();
        throw std::logic_error("Able to send authenticated requests when logged out");
    } catch (std::runtime_error&) {
        // ALl good
    }

    const std::string username_1 = generateRandomString(8);
    auto password_1 = SecureMemoryBuffer::create(32);
    memcpy(password_1->data(), "correct horse staple battery", 28);
    qDebug() << "Registering second user";
    register_user(username_1, std::move(password_1));
    qDebug() << "Registering second user's device";
    register_first_device();
    qDebug() << "Logging in second user";
    auto loginPassword1 = SecureMemoryBuffer::create(32);
    memcpy(loginPassword1->data(), "correct horse staple battery", 28);
    login_user(username_1, std::move(loginPassword1), false);
    qDebug() << "Logging out second user";
    logout();

    qDebug() << "Attempting login with first user's original password";
    try {
        auto oldPassword = SecureMemoryBuffer::create(32);
        memcpy(oldPassword->data(), "password1234", 11);
        login_user(username, std::move(oldPassword));
        throw std::logic_error("Login succeeded with old password");
    } catch (std::runtime_error &) {
        // All good
    }

    qDebug() << "Attempting login with second user's password";
    try {
        auto otherPassword = SecureMemoryBuffer::create(32);
        memcpy(otherPassword->data(), "correct horse staple battery", 28);
        login_user(username, std::move(otherPassword));
        throw std::logic_error("Login succeeded with other user's password");
    } catch (std::runtime_error &) {
        // All good
    }

    qDebug() << "Logging in first user with new password";
    auto newLoginPassword = SecureMemoryBuffer::create(32);
    memcpy(newLoginPassword->data(), "even_stronger_password", 21);
    login_user(username, std::move(newLoginPassword), false);

    qDebug() << "Registering second device for first user";
    const std::string new_device_name = "device 2";
    unsigned char pk_device[crypto_sign_PUBLICKEYBYTES];
    const auto sk_device = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(pk_device, sk_device->data());
    add_trusted_device(pk_device, new_device_name);

    logout();
    auto password1_copy = SecureMemoryBuffer::create(32);
    memcpy(password1_copy->data(), "correct horse staple battery", 28);
    login_user(username_1, std::move(password1_copy), false);
    generate_signed_prekey();

    // Create a temporary file
    const std::string temp_file_path = "/tmp/test_file.txt";
    std::ofstream temp_file(temp_file_path);
    temp_file << "This is a test file content";
    temp_file.close();

    qDebug() << "Uploading file";
    const auto file_key = SecureMemoryBuffer::create(SYM_KEY_LEN);
    randombytes_buf(file_key->data(), SYM_KEY_LEN);
    const std::string uuid = upload_file(temp_file_path, file_key);

    qDebug() << "Sending file to second user";
    send_file_to(username, temp_file_path);
    std::remove(temp_file_path.c_str());

    qDebug() << "Deleting file";
    post_delete_file(uuid);

    std::cout << "Integration main flow test completed successfully." << std::endl;
}
