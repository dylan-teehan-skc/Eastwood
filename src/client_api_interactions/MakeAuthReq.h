#ifndef MAKE_AUTH_REQ_H
#define MAKE_AUTH_REQ_H

#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

json post(const std::string& endpoint, const json& data);
json get(const std::string& endpoint = "/");

#endif // MAKE_AUTH_REQ_H