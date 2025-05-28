#ifndef SIGNUP_H
#define SIGNUP_H
#include <string>
#include <memory>

int register_user(const std::string &username, const std::unique_ptr<const std::string> &master_password);

#endif //SIGNUP_H
