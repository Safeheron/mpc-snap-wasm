#include "key_recovery_context_param.h"
#include <crypto-bip39/bip39.h>
#include "third_party/nlohmann/json.hpp"
#include "../common/tools.h"
#include "../common/json_helper_ex.h"

KeyRecoveryContextParam::KeyRecoveryContextParam()
: curve_type_(safeheron::curve::CurveType::INVALID_CURVE)
{
}

bool KeyRecoveryContextParam::FromJson(const char *str, int size, std::string &err_msg)
{
    nlohmann::json root;
    if (!parse_json_str(str, size, root, err_msg)) return false;

    int num;
    if (!json_helper::fetch_json_int_node(root, "curve_type", num, err_msg)) return false;
    if (num != static_cast<int>(safeheron::curve::CurveType::SECP256K1) &&
        num != static_cast<int>(safeheron::curve::CurveType::P256) &&
        num != static_cast<int>(safeheron::curve::CurveType::ED25519)) {
        err_msg = "Invalid curve type.";
        return false;
    }
    curve_type_ = static_cast<safeheron::curve::CurveType>(num);

    std::string mnemonic;
    if (!json_helper::fetch_json_string_node(root, "mnemo", mnemonic, err_msg)) return false;
    std::string bytes;
    bool ok = safeheron::bip39::MnemonicToBytes(bytes, mnemonic, safeheron::bip39::Language::ENGLISH);
    if (!ok) {
        err_msg = "Failed to convert mnemonics to bytes.";
        return false;
    }

    try {
        x_ = safeheron::bignum::BN::FromBytesBE(bytes);
    } catch (std::exception &e) {
        err_msg = e.what();
        return false;
    }

    if (!json_helper::fetch_json_bn_node(root, "i", i_, err_msg)) return false;

    if (!json_helper::fetch_json_bn_node(root, "j", j_, err_msg)) return false;

    if (!json_helper::fetch_json_bn_node(root, "k", k_, err_msg)) return false;

    if (!json_helper::fetch_json_string_node(root, "local_party_id", local_party_id_, err_msg)) return false;

    if (!json_helper::fetch_json_string_node(root, "remote_party_id", remote_party_id_, err_msg)) return false;

    return true;
}

