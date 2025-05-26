#ifndef MAKE_UNAUTH_REQ_H
#define MAKE_UNAUTH_REQ_H

#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

std::string post_unauth(const json& data, const std::string& endpoint = "/");
std::string get_unauth(const std::string& endpoint = "/");

#endif // MAKE_UNAUTH_REQ_H