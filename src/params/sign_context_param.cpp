#include "sign_context_param.h"
#include "nlohmann/json.hpp"
#include "../common/tools.h"
#include "../common/json_helper_ex.h"

namespace safeheron {
namespace mpc_snap_wasm {
namespace params {

bool SignContextParam::FromJson(const char *str, int size, std::string &err_msg) {
    nlohmann::json root;
    if (!safeheron::mpc_snap_wasm::common::parse_json_str(str, size, root, err_msg)) return false;

    if (!json_helper::fetch_json_string_node(root, "sign_key", sign_key_, err_msg)) return false;

    if (!json_helper::fetch_json_bn_node(root, "digest", digest_, err_msg)) return false;

    nlohmann::json participants_node;
    if (!json_helper::fetch_json_array_node(root, "participants", participants_node, err_msg)) return false;
    for (nlohmann::json::iterator it = participants_node.begin(); it != participants_node.end(); ++it) {
        participants_.push_back(*it);
    }

    if (!json_helper::fetch_json_string_node(root, "sid", sid_, err_msg)) return false;

    return true;
}

}
}
}