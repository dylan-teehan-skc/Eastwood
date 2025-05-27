#ifndef JSON_PARSER_H
#define JSON_PARSER_H

#include <string>
#include <nlohmann/json.hpp>

namespace webwood {
    class HttpError : public std::runtime_error {
    public:
        explicit HttpError(const std::string& message, int status_code) 
            : std::runtime_error(message), status_code_(status_code) {}
        int get_status_code() const { return status_code_; }
    private:
        int status_code_;
    };

    nlohmann::json parse_json_response(const std::string& response);
}

#endif // JSON_PARSER_H 