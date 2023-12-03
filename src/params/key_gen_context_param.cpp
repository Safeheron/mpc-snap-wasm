#include "key_gen_context_param.h"
#include "nlohmann/json.hpp"
#include "../common/tools.h"
#include "../common/json_helper_ex.h"

namespace safeheron {
namespace mpc_snap_wasm {
namespace params {

KeyGenContextParam::KeyGenContextParam()
: curve_type_(safeheron::curve::CurveType::INVALID_CURVE)
, n_parties_(0)
, threshold_(0)
, prepared_(false)
{ }

bool KeyGenContextParam::FromJson(const char *str, int size, std::string &err_msg) {
    nlohmann::json root;
    if (!safeheron::mpc_snap_wasm::common::parse_json_str(str, size, root, err_msg)) return false;

    int num;
    if (!json_helper::fetch_json_int_node(root, "curve_type", num, err_msg)) return false;
    if (num != static_cast<int>(safeheron::curve::CurveType::SECP256K1) &&
        num != static_cast<int>(safeheron::curve::CurveType::P256) &&
        num != static_cast<int>(safeheron::curve::CurveType::ED25519)) {
        err_msg = "Invalid curve type.";
        return false;
    }
    curve_type_ = static_cast<safeheron::curve::CurveType>(num);

    if (!json_helper::fetch_json_int_node(root, "n_parties", n_parties_, err_msg)) return false;
    if (!json_helper::fetch_json_int_node(root, "threshold", threshold_, err_msg)) return false;

    if (!json_helper::fetch_json_string_node(root, "party_id", party_id_, err_msg)) return false;
    if (!json_helper::fetch_json_bn_node(root, "index", index_, err_msg)) return false;

    nlohmann::json remote_parties;
    if (!json_helper::fetch_json_array_node(root, "remote_parties", remote_parties, err_msg)) return false;
    for (nlohmann::json::iterator it = remote_parties.begin(); it != remote_parties.end(); ++it) {
        nlohmann::json &remote_party_node = *it;
        std::string remote_party_id;
        safeheron::bignum::BN remote_party_index;
        if (!json_helper::fetch_json_string_node(remote_party_node, "party_id", remote_party_id,
                                                 err_msg))
            return false;
        if (!json_helper::fetch_json_bn_node(remote_party_node, "index", remote_party_index, err_msg))
            return false;
        remote_party_id_arr_.push_back(remote_party_id);
        remote_party_index_arr_.push_back(remote_party_index);
    }

    if (!json_helper::fetch_json_string_node(root, "sid", sid_, err_msg)) return false;

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
    } else {
        prepared_ = false;
    }

    return true;
}

}
}
}