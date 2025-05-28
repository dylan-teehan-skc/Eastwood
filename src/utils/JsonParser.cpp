#include "JsonParser.h"

namespace webwood {

std::string extract_response_body(const std::string& response) {
    size_t json_start = response.find("\r\n\r\n");
    if (json_start == std::string::npos) {
        json_start = response.find("\n\n");
        if (json_start == std::string::npos) {
            return response;  // Return full response if no body separator found
        }
        json_start += 2;
    } else {
        json_start += 4;
    }
    return response.substr(json_start);
}

int parse_status_code(const std::string& first_line) {
    size_t first_space = first_line.find(' ');
    if (first_space == std::string::npos) {
        return 0;
    }
    
    size_t second_space = first_line.find(' ', first_space + 1);
    if (second_space == std::string::npos) {
        return 0;
    }
    
    try {
        return std::stoi(first_line.substr(first_space + 1, second_space - first_space - 1));
    } catch (const std::exception&) {
        return 0;
    }
}

nlohmann::json parse_json_response(const std::string& response) {
    if (response.empty()) {
        throw HttpError("Empty response received", 0);
    }

    // Extract status code from the first line
    size_t first_line_end = response.find("\r\n");
    if (first_line_end == std::string::npos) {
        first_line_end = response.find("\n");
    }
    if (first_line_end == std::string::npos) {
        throw HttpError("Invalid response format", 0);
    }

    std::string first_line = response.substr(0, first_line_end);
    int status_code = parse_status_code(first_line);

    // If status code indicates an error (4xx or 5xx), throw HttpError
    if (status_code >= 400) {
        throw HttpError(extract_response_body(response), status_code);
    }

    std::string body = extract_response_body(response);

    // Extract and parse the JSON body
    try {
        nlohmann::json body_json = nlohmann::json::parse(body);
        return {{"data", body_json}, {"content_type", "json"}, {"status_code", status_code}};
    } catch (const nlohmann::json::parse_error&) {
        return {{"data", body}, {"content_type", "text"}, {"status_code", status_code}};
    }
}

}