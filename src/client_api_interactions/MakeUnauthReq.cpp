#include <sodium.h>
#include <iostream>
#include "src/libraries/HTTPSClient.h"
#include "../utils/ConversionUtils.h"
#include "../utils/JsonParser.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

json post_unauth(const std::string& endpoint, const json& data) {
    std::string API_HOST = load_env_variable("API_HOST");
    if (API_HOST.empty()) {
        std::cerr << "API_HOST not found in .env file" << std::endl;
        return {{"error", "API_HOST not found"}};
    }

    std::string headers = "Content-Type: application/json\n";

    webwood::HTTPSClient httpsclient;
    std::string request_body = data.dump();
    std::string response = httpsclient.post(API_HOST, endpoint, headers, request_body);
    
    try {
        return webwood::parse_json_response(response);
    } catch (const webwood::HttpError& e) {
        throw webwood::HttpError(webwood::extract_response_body(response), e.get_status_code());
    } catch (const std::exception& e) {
        throw webwood::HttpError(webwood::extract_response_body(response), 0);
    }
}

json get_unauth(const std::string& endpoint = "/") {
    std::string API_HOST = load_env_variable("API_HOST");
    if (API_HOST.empty()) {
        std::cerr << "API_HOST not found in .env file" << std::endl;
        return {{"error", "API_HOST not found"}};
    }

    std::string headers;
    
    webwood::HTTPSClient httpsclient;
    std::string response = httpsclient.get(API_HOST, endpoint, headers);
    
    try {
        return webwood::parse_json_response(response);
    } catch (const webwood::HttpError& e) {
        throw webwood::HttpError(webwood::extract_response_body(response), e.get_status_code());
    } catch (const std::exception& e) {
        throw webwood::HttpError(webwood::extract_response_body(response), 0);
    }
}