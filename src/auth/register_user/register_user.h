#ifndef SIGNUP_H
#define SIGNUP_H
#include <string>
#include <memory>

void register_user(const std::string &username, const std::unique_ptr<const std::string> &master_password,
                  const bool DEBUG_REFRESH_TABLES = false);

#endif //SIGNUP_H
