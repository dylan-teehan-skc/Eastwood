#include "login.h"

#include "src/endpoints/endpoints.h"
#include "src/keys/session_token_manager.h"
#include "src/sql/queries.h"

/*
let nonce = POST requestLogin {username, device_public}
let sessionToken = POST authenticate {username, device_public, nonce_signature}
body : {
    status: "authenticated",
    token: <base64>
*/

void login_user(const std::string &username) {
    const auto [pk_device, sk_device] = get_decrypted_keypair("device");

    const auto nonce = post_request_login(username, q_byte_array_to_chars(pk_device));
    unsigned char signature[crypto_sign_BYTES];
    crypto_sign_detached(signature, nullptr, nonce.data(), nonce.size(), sk_device->data());
    const std::string token = post_authenticate(username, q_byte_array_to_chars(pk_device), signature);
    SessionTokenManager::instance().setToken(token);
}
