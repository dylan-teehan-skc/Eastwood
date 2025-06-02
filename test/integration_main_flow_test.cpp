#include "ui/windows/login/login.h"
#include "./libraries/HTTPSClient.h"
#include <iostream>
#define SQLITE_HAS_CODEC 1
#include <random>

#include "auth/login/login.h"
#include "auth/register_device/register_device.h"
#include "auth/register_user/register_user.h"
#include "client_api_interactions/MakeAuthReq.h"
#include "database/database.h"
#include "endpoints/endpoints.h"
#include "sql/queries.h"
#include <memory>

#include "auth/logout.h"
#include "src/auth/rotate_master_key/rotate_master_key.h"

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
    const auto password = std::make_unique<const std::string>("password1234");

    qDebug() << "Registering user";
    register_user(username, password);
    qDebug() << "Registering device";
    register_first_device();
    qDebug() << "Logging in";
    login_user(username, password);
    const auto new_password = std::make_unique<const std::string>("even_stronger_password");
    qDebug() << "Rotating password";
    rotate_master_password(username, *new_password.get());
    qDebug() << "Posting keybundles";
    post_new_keybundles(
        get_decrypted_keypair("device"),
        generate_signed_prekey(),
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
    const auto password_1 = std::make_unique<const std::string>("correct horse staple battery");
    qDebug() << "Registering second user";
    register_user(username_1, password_1);
    qDebug() << "Registering second user's device";
    register_first_device();
    qDebug() << "Logging in second user";
    login_user(username_1, password_1);
    qDebug() << "Logging out second user";
    logout();

    qDebug() << "Attempting login with first user's original password";
    try {
        login_user(username, password);
        throw std::logic_error("Login succeeded with old password");
    } catch (std::runtime_error &) {
        // All good
    }

    qDebug() << "Attempting login with second user's password";
    try {
        login_user(username, password_1);
        throw std::logic_error("Login succeeded with other user's password");
    } catch (std::runtime_error &) {
        // All good
    }

    qDebug() << "Logging in first user with new password";
    login_user(username, new_password);

    qDebug() << "Registering second device for first user";
    const std::string new_device_name = "device 2";
    unsigned char pk_device[crypto_sign_PUBLICKEYBYTES];
    const auto sk_device = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(pk_device, sk_device->data());

    add_trusted_device(pk_device, new_device_name);


    std::cout << "Integration main flow test completed successfully." << std::endl;
}
