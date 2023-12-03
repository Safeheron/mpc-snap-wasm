#include "minimal_key_param.h"
#include <algorithm>
#include <crypto-bip39/bip39.h>
#include <crypto-encode/hex.h>
#include <crypto-hash/safe_hash256.h>
#include <crypto-zkp/dlog_proof_v2.h>
#include "nlohmann/json.hpp"
#include "../common/tools.h"
#include "../common/json_helper_ex.h"

namespace safeheron {
namespace mpc_snap_wasm {
namespace params {

MinimalKeyParam::MinimalKeyParam()
: curve_type_(safeheron::curve::CurveType::INVALID_CURVE)
, n_parties_(0)
, threshold_(0)
{ }

bool MinimalKeyParam::FromJson(const char *str, int size, std::string &err_msg) {
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

    std::string mnemo;
    if (!json_helper::fetch_json_string_node(root, "mnemo", mnemo, err_msg)) return false;
    std::string bytes;
    bool ok = safeheron::bip39::MnemonicToBytes(bytes, mnemo, safeheron::bip39::Language::ENGLISH);
    if (!ok) {
        err_msg = "Failed to convert mnemonics to bytes.";
        return false;
    }

    std::string verify_mneno;
    ok = safeheron::bip39::BytesToMnemonic(verify_mneno, bytes, safeheron::bip39::Language::ENGLISH);
    if (!ok) {
        err_msg = "Failed to covert bytes to mnemonic.";
        return false;
    }
    if (mnemo != verify_mneno) {
        err_msg = "Secondary verification of mnemonics to bytes failed.";
        return false;
    }

    try {
        x_ = safeheron::bignum::BN::FromBytesBE(bytes);
    } catch (std::exception &e) {
        err_msg = e.what();
        return false;
    }

    if (!json_helper::fetch_json_curve_point_node(root, "X", curve_type_, X_, err_msg)) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(curve_type_);
    if (curv->g * x_ != X_) {
        err_msg = "The public key can not match the related private key.";
        return false;
    }

    nlohmann::json remote_parties;
    if (!json_helper::fetch_json_array_node(root, "remote_parties", remote_parties, err_msg)) return false;
    for (nlohmann::json::iterator it = remote_parties.begin(); it != remote_parties.end(); ++it) {
        nlohmann::json &remote_party_node = *it;
        std::string remote_party_id;
        safeheron::bignum::BN remote_party_index;
        safeheron::curve::CurvePoint remote_X;
        std::string remote_dlog_zkp;
        if (!json_helper::fetch_json_string_node(remote_party_node, "party_id", remote_party_id,
                                                 err_msg))
            return false;
        if (!json_helper::fetch_json_bn_node(remote_party_node, "index", remote_party_index,
                                             err_msg))
            return false;
        if (!json_helper::fetch_json_curve_point_node(remote_party_node, "X", curve_type_, remote_X,
                                                      err_msg))
            return false;
        if (!json_helper::fetch_json_string_node(remote_party_node, "dlog_zkp", remote_dlog_zkp,
                                                 err_msg))
            return false;

        safeheron::zkp::dlog::DLogProof_V2 dlog_zkp;
        ok = dlog_zkp.FromBase64(remote_dlog_zkp);
        if (!ok) {
            err_msg = "Failed to call dlog_zkp.FromBase64(remote_dlog_zkp).";
            return false;
        }
        if (!dlog_zkp.Verify(remote_X)) {
            err_msg = "Failed to verify remote public key.";
            return false;
        }

        remote_party_id_arr_.push_back(remote_party_id);
        remote_party_index_arr_.push_back(remote_party_index);
        remote_X_arr_.push_back(remote_X);
    }

    return true;
}

std::string MinimalKeyParam::gen_rid() {
    std::vector<safeheron::bignum::BN> indexes;
    std::vector<safeheron::curve::CurvePoint> points;
    indexes.push_back(index_);
    points.push_back(X_);
    for (size_t i = 0; i < remote_party_index_arr_.size(); ++i) {
        indexes.push_back(remote_party_index_arr_[i]);
        points.push_back(remote_X_arr_[i]);
    }

    std::vector<safeheron::bignum::BN> sorted_indexes = indexes;
    std::sort(sorted_indexes.begin(), sorted_indexes.end());

    safeheron::hash::CSafeHash256 sha256;
    uint8_t digest[safeheron::hash::CSafeHash256::OUTPUT_SIZE];
    for (size_t i = 0; i < sorted_indexes.size(); ++i) {
        for (size_t j = 0; j < indexes.size(); ++j) {
            if (sorted_indexes[i] == indexes[j]) {
                std::string buf;
                indexes[j].ToBytesBE(buf);
                sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
                points[j].x().ToBytesBE(buf);
                sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
                points[j].y().ToBytesBE(buf);
                sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
            }
        }
    }
    sha256.Finalize(digest);

    return std::string((const char *) digest, sizeof(digest));
}

}
}
}