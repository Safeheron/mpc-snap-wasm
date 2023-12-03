#include "json_helper.h"

namespace json_helper {

auto isNumber = [](const JSON &node) { return node.is_number(); };
auto isString = [](const JSON &node) { return node.is_string(); };
auto isArray = [](const JSON &node) { return node.is_array(); };
auto isOject = [](const JSON &node) { return node.is_object(); };
auto isBoolean = [](const JSON &node) { return node.is_boolean(); };

template<typename T>
bool fetch_json_node_value(const JSON &root, const std::string &node_name, T &value,
                           std::function<bool(const JSON &)> check_type_func,
                           std::string &err_msg) {
    char msg[256] = {0};

    try {
        auto it = root.find(node_name);
        if (it == root.end()) {
            snprintf(msg, sizeof(msg) - 1, "Invalid json! node '%s' is not exist!",
                     node_name.c_str());
            err_msg = msg;
            return false;
        }
        if (!check_type_func(it.value())) {
            snprintf(msg, sizeof(msg) - 1,
                     "Invalid json! node '%s' does not have the expected type!",
                     node_name.c_str());
            err_msg = msg;
            return false;
        }
        value = it->get<T>();
    } catch (JSON::exception &e) {
        snprintf(msg, sizeof(msg) - 1,
                 "Invalid json! Encounter an exception: %s", e.what());
        err_msg = msg;
        return false;
    }

    return true;
}

bool fetch_json_string_node(const JSON &root, const std::string &node_name,
                            std::string &value, std::string &err_msg) {
    return fetch_json_node_value(root, node_name, value, isString, err_msg);
}

bool fetch_json_int_node(const JSON &root, const std::string &node_name, int &value,
                         std::string &err_msg) {
    return fetch_json_node_value(root, node_name, value,
                                 isNumber, err_msg);
}

bool fetch_json_bool_node(const JSON &root, const std::string &node_name, bool &value,
                          std::string &err_msg){
    return fetch_json_node_value(root, node_name, value,
                                 isBoolean, err_msg);
}

bool fetch_json_long_node(const JSON &root, const std::string &node_name, long &value,
                          std::string &err_msg) {
    return fetch_json_node_value(root, node_name, value, isNumber, err_msg);
}

bool fetch_json_array_node(const JSON &root, const std::string &node_name, JSON &value,
                           std::string &err_msg) {
    return fetch_json_node_value(root, node_name, value, isArray, err_msg);
}

bool fetch_json_object_node(const JSON &root, const std::string &node_name, JSON &value,
                            std::string &err_msg) {
    return fetch_json_node_value(root, node_name, value, isOject, err_msg);
}

}