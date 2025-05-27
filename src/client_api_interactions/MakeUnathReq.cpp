#include <sodium.h>
#include <iostream>
#include "src/libraries/HTTPSClient.h"
#include "../utils/HtmlParser.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

std::string post_unauthenticated(const std::string& data, const std::string& endpoint = "/") {
    const char* env_api_host = std::getenv("API_HOST");
    if (env_api_host == nullptr) {
        std::cerr << "API_HOST environment variable is not set" << std::endl;
        return "";
    }

    const std::string API_HOST(env_api_host);
    const std::string API_PATH = API_HOST + endpoint;

    webwood::HTTPSClient httpsclient;
    std::string response = httpsclient.post(API_HOST, API_PATH, data);

    try {
        nlohmann::json parsed_response = webwood::parse_html_to_json(response);
        return parsed_response;
    } catch (const webwood::HttpError& e) {
        std::cerr << "HTTP Error: " << e.what() << std::endl;
        throw;
    } catch (const std::exception& e) {
        std::cerr << "Error parsing response: " << e.what() << std::endl;
        throw;
    }
}

std::string get_unauthenticated(const std::string& endpoint = "/") {
    const char* env_api_host = std::getenv("API_HOST");
    if (env_api_host == nullptr) {
        std::cerr << "API_HOST environment variable is not set" << std::endl;
        return "";
    }

    const std::string API_HOST(env_api_host);
    const std::string API_PATH = API_HOST + endpoint;

    webwood::HTTPSClient httpsclient;
    std::string response = httpsclient.get(API_HOST, API_PATH);

    try {
        nlohmann::json parsed_response = webwood::parse_html_to_json(response);
        return parsed_response;
    } catch (const webwood::HttpError& e) {
        std::cerr << "HTTP Error: " << e.what() << std::endl;
        throw;
    } catch (const std::exception& e) {
        std::cerr << "Error parsing response: " << e.what() << std::endl;
        throw;
    }
}