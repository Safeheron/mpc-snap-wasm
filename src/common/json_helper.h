#ifndef TEE_JSON_HELPER_H
#define TEE_JSON_HELPER_H

#include "nlohmann/json.hpp"
#include <string>
#include <functional>

namespace json_helper {

using JSON = nlohmann::json;

template<typename T>
bool fetch_json_node_value(const JSON &root, const std::string &node_name, T &value,
                           std::function<bool(const JSON &)> check_type_func,
                           std::string &err_msg);

bool fetch_json_string_node(const JSON &root, const std::string &node_name,
                            std::string &value, std::string &err_msg);

bool fetch_json_int_node(const JSON &root, const std::string &node_name, int &value,
                         std::string &err_msg);

bool fetch_json_bool_node(const JSON &root, const std::string &node_name, bool &value,
                         std::string &err_msg);

bool fetch_json_long_node(const JSON &root, const std::string &node_name, long &value,
                          std::string &err_msg);

bool fetch_json_array_node(const JSON &root, const std::string &node_name, JSON &value,
                           std::string &err_msg);

bool fetch_json_object_node(const JSON &root, const std::string &node_name, JSON &value,
                            std::string &err_msg);
}

#endif //TEE_JSON_HELPER_H