#ifndef MAKE_AUTH_REQ_H
#define MAKE_AUTH_REQ_H

#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

json post(const json& data, const std::string& endpoint = "/");
json get(const std::string& endpoint = "/");

#endif // MAKE_AUTH_REQ_H