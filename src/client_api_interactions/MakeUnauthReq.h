#ifndef MAKE_UNAUTH_REQ_H
#define MAKE_UNAUTH_REQ_H

#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

json post_unauth(const json& data, const std::string& endpoint = "/");
json get_unauth(const std::string& endpoint = "/");

#endif // MAKE_UNAUTH_REQ_H