
#ifndef SET_UP_CLIENT_H
#define SET_UP_CLIENT_H
#include <memory>
#include <string>


void set_up_client_for_user(
    const std::string &username,
    const std::unique_ptr<const std::string> &master_password,
    const bool DEBUG_REFRESH_TABLES = false
);

#endif //SET_UP_CLIENT_H
