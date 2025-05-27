#include "JsonParser.h"

namespace webwood {

nlohmann::json parse_json_response(const std::string& response) {
    if (response.empty()) {
        return {{"data", ""}, {"content_type", "text"}};
    }

    size_t json_start = response.find("\r\n\r\n");
    if (json_start == std::string::npos) {
        json_start = response.find("\n\n");
        if (json_start == std::string::npos) {
            return {{"data", response}, {"content_type", "text"}};
        }
        json_start += 2;
    } else {
        json_start += 4;
    }

    // Extract and parse the JSON body
    try {
        nlohmann::json body_json = nlohmann::json::parse(response.substr(json_start));
        return {{"data", body_json}, {"content_type", "json"}};
    } catch (const nlohmann::json::parse_error&) {
        return {{"data", response.substr(json_start)}, {"content_type", "text"}};
    }
}

}