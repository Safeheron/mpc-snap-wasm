#include "tools.h"
namespace safeheron {
namespace mpc_snap_wasm {
namespace common {
std::string get_err_stack_info(const safeheron::mpc_flow::mpc_parallel_v2::MPCContext *ctx) {
    std::vector<safeheron::mpc_flow::mpc_parallel_v2::ErrorInfo> err_stack;
    ctx->get_error_stack(err_stack);
    std::string err_info = "";
    for (const auto &err: err_stack) {
        err_info += err.info_ + "\n";
    }
    return err_info;
}

int err_msg_ret(const int err_code, const std::string &err_info, const std::string &file_name,
                const std::string &func_name, const int line_num, char *out, int *out_size) {
    nlohmann::json output_json;
    nlohmann::json err_json;
    err_json["err_code"] = err_code;
    std::string err_msg = err_info + " In file: " + file_name + ", function: " + func_name + ", line: " +
                          std::to_string(line_num) + ".\n";
    err_json["err_msg"] = err_msg;
    output_json["err"] = err_json;
    std::string output_str = output_json.dump();
    if (!out || *out_size < (int) output_str.length()) {
        return -2;
    }
    memcpy(out, output_str.c_str(), output_str.length());
    *out_size = (int) output_str.length();
    return -1;
}

bool parse_json_str(const char *str, int size, nlohmann::json &json, std::string &err_msg) {
    if (!str || size <= 0) {
        err_msg = "Invalid input.";
        return false;
    }
    try {
        std::string in_str;
        in_str.assign(str, size);
        json = nlohmann::json::parse(in_str);
    } catch (nlohmann::json::parse_error &e) {
        err_msg = "Failed to parse json str: ";
        err_msg += e.what();
        return false;
    }

    return true;
}

bool serialize_json_node(const nlohmann::json &json, char *str, int *size, std::string &err_msg) {
    std::string out_str = json.dump();
    if (!str || *size < (int) out_str.length()) {
        err_msg = "The output buffer is too short.";
        return false;
    }

    memcpy(str, out_str.c_str(), out_str.length());
    *size = (int) out_str.length();

    return true;
}
}
}
}