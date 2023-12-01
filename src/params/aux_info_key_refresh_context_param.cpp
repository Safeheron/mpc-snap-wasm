#include "aux_info_key_refresh_context_param.h"
#include "nlohmann/json.hpp"
#include "../common/json_helper_ex.h"
#include "../common/tools.h"

namespace safeheron {
namespace mpc_snap_wasm {
namespace params {

KeyRefreshContextParam::KeyRefreshContextParam()
: n_parties_(0)
, update_flag_(true)
, prepared_(false)
{ }

bool KeyRefreshContextParam::FromJson(const char *str, int size, std::string &err_msg) {
    nlohmann::json root;
    if (!safeheron::mpc_snap_wasm::common::parse_json_str(str, size, root, err_msg)) return false;

    if (!json_helper::fetch_json_int_node(root, "n_parties", n_parties_, err_msg)) return false;

    std::string minimal_sign_key_base64;
    if (!json_helper::fetch_json_string_node(root, "minimal_sign_key", minimal_sign_key_base64, err_msg))
        return false;

    bool ok = minimal_sign_key_.FromBase64(minimal_sign_key_base64);
    if (!ok) {
        err_msg = "Unable to deserialize minimal sign key.";
        return false;
    }

    if (!json_helper::fetch_json_string_node(root, "sid", sid_, err_msg)) return false;

    if (root.find("update_key_shares") != root.end()) {
        if (!json_helper::fetch_json_bool_node(root, "update_key_shares", update_flag_, err_msg))
            return false;
    }

    if (root.find("prepared_data") != root.end()) {
        nlohmann::json prepared_data_node;
        if (!json_helper::fetch_json_object_node(root, "prepared_data", prepared_data_node, err_msg))
            return false;
        if (!json_helper::fetch_json_bn_node(prepared_data_node, "N", N_, err_msg)) return false;
        if (!json_helper::fetch_json_bn_node(prepared_data_node, "s", s_, err_msg)) return false;
        if (!json_helper::fetch_json_bn_node(prepared_data_node, "t", t_, err_msg)) return false;
        if (!json_helper::fetch_json_bn_node(prepared_data_node, "p", p_, err_msg)) return false;
        if (!json_helper::fetch_json_bn_node(prepared_data_node, "q", q_, err_msg)) return false;
        if (!json_helper::fetch_json_bn_node(prepared_data_node, "alpha", alpha_, err_msg)) return false;
        if (!json_helper::fetch_json_bn_node(prepared_data_node, "beta", beta_, err_msg)) return false;
        prepared_ = true;
    }

    return true;
}

}
}
}