#include <emscripten.h>
#include <vector>
#include <crypto-encode/hex.h>
#include <crypto-bip39/bip39.h>
#include <multi-party-ecdsa/cmp/key_recovery/context.h>
#include <multi-party-ecdsa/cmp/util.h>
#include "nlohmann/json.hpp"
#include "params/key_recovery_context_param.h"
#include "params/exchange_message_param.h"
#include "common/thread_safe_pointer_container.h"
#include "common/json_helper_ex.h"
#include "common/tools.h"
#include "common/global_variables.h"

#define RELEASE_OBJ(a) {if (a){delete a; a=nullptr;}}

#ifdef __cplusplus
extern "C" {
#endif

using safeheron::multi_party_ecdsa::cmp::key_recovery::Context;
static safeheron::mpc_snap_wasm::common::ThreadSafePointerContainer<safeheron::multi_party_ecdsa::cmp::key_recovery::Context> context_container;

/**
 * A wrapper of third_party/multi-party-sig-cpp/src/multi-party-sig/multi-party-ecdsa/cmp/key_recovery protocol
 */

/**
 * curve_type : specific elliptic curve
 * - 1 represents Secp256k1
 * - 2 represents P256
 * - 2^5 represents ED25519
 */
/**
 * @param[in] in JSON
 * {
 *   "curve_type": 1
 *   //local secret key shard
 *   "mnemo": "spot lobster indicate blossom ketchup budget sniff way hungry sun mansion antenna dignity stairs advance click chief all desert diary task aim guilt coil"
 *   "i": "1" //local party index
 *   "j": "2" //remote party index
 *   "k": "3" //recovered party index (which lost the key)
 *   "local_party_id": "party_1"
 *   "remote_party_id": "party_2"
 * }
 * @param[in] in_size length of the input
 * @param[out] out JSON
 * {
 *   "context": "684602"
 *   "current_round_index": 0
 *   "out_message_list":
 *   [
 *     {
 *       "p2p_message": "Co8BCkA3ODI2...OUUzMjFCRjU1RDlCRjgyODI4QTg3"
 *       "broadcast_message": ""
 *       "source": "party_1"
 *       "destination": "party_2"
 *     },
 *   ]
 * }
 * If errors occur, output:
 * {
 *   "err":
 *   {
 *     "err_code": 1
 *     "err_msg": "xx xx"
 *   }
 * }
 * @param[in/out] out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE kr_create_context_compute_round0(const char *in, int in_size,
                                                          char *out, int *out_size) {
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Random seed is not set!", __FILE__,__FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    // parse context param
    safeheron::mpc_snap_wasm::params::KeyRecoveryContextParam key_recovery_context_param;
    if (!key_recovery_context_param.FromJson(in, in_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__,__FUNCTION__, __LINE__, out, out_size);
    }

    // new context
    safeheron::multi_party_ecdsa::cmp::key_recovery::Context *ctx = nullptr;
    if (!(ctx = new safeheron::multi_party_ecdsa::cmp::key_recovery::Context())) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Failed to new Context.", __FILE__,__FUNCTION__, __LINE__, out, out_size);
    }

    // fill the context
    bool ok = safeheron::multi_party_ecdsa::cmp::key_recovery::Context::CreateContext(*ctx, key_recovery_context_param.curve_type_, key_recovery_context_param.x_, key_recovery_context_param.i_, key_recovery_context_param.j_, key_recovery_context_param.k_, key_recovery_context_param.local_party_id_, key_recovery_context_param.remote_party_id_);
    if (!ok) {
        RELEASE_OBJ(ctx)
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "CreateContext failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // push message
    if (!ctx->PushMessage()) {
        RELEASE_OBJ(ctx)
        err_msg = safeheron::mpc_snap_wasm::common::get_err_stack_info(ctx);
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // pop message
    std::vector<std::string> out_p2p_msg_arr;
    std::string out_broadcast_msg;
    std::vector<std::string> out_des_arr;
    if (!ctx->PopMessages(out_p2p_msg_arr, out_broadcast_msg, out_des_arr)) {
        RELEASE_OBJ(ctx)
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "PopMessage failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // fill the output message
    safeheron::mpc_snap_wasm::params::ExchangeMsgParam out_msg;
    out_msg.context_ = std::to_string(reinterpret_cast<std::uintptr_t>(ctx));
    out_msg.current_round_index_ = ctx->get_cur_round();;
    for (size_t i = 0; i < out_des_arr.size(); ++i) {
        safeheron::mpc_snap_wasm::params::ExchangeMsgParam::Message msg;
        msg.p2p_message_ = out_p2p_msg_arr.empty() ? std::string(): out_p2p_msg_arr[i];
        msg.broadcast_message_ = out_broadcast_msg;
        msg.destination_ = out_des_arr[i];
        msg.source_ = ctx->local_party_.party_id_;
        out_msg.message_list_.push_back(msg);
    }

    // get the result JSON string
    if (!out_msg.ToJson(out, out_size, err_msg)) {
        RELEASE_OBJ(ctx)
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // save the context
    context_container.Push(ctx);

    return 0;
}

/**
 * @param[in] in JSON
 * {
 *   "context" : "684602"
 *   "last_round_index": 1
 *   "in_message_list":
 *   [
 *     {
 *       "p2p_message": "Co8BCkBGOEM0...RkFEOTAwQUNFM0QwRUYxMzA3OUEx"
 *       "broadcast_message": ""
 *       "source": "party_2"
 *       "destination": "party_1"
 *     },
 *   ]
 * }
 * @param[in] in_size length of the input
 * @param[out] out JSON
 * Middle round output:
 * {
 *   "context": "684602"
 *   "current_round_index": 2
 *   "out_message_list":
 *   [
 *     {
 *       "p2p_message": "Co8BCkA3ODI2...OUUzMjFCRjU1RDlCRjgyODI4QTg3"
 *       "broadcast_message": ""
 *       "source": "party_1"
 *       "destination": "party_2"
 *     },
 *   ]
 * }
 * Final round output:
 * {
 *   "x_ki": "9C07351F11F4101DD68493CAE5186ABD898E97B6C40FA16D5B55592741CA4AF8" //partial secret key shard of the recovered party
 *   "X_k": "0438d9427db939b1ac734fe2e95469aced65d0692f418e68d395321365f651bb00e6342042a47ef0cd3cf3d496d7aa254043e565b32906d0dbfd94450a954408fc" //public key of the recovered party
 *   "pub": "0404a55407faee30554604bac5ff3911bfdfee6be2ca1fe06d2e9c42a42030d961cecb11707a5b75f19d842980dc2f09df9f125f15412b55b3ff4440ab195a3ac4"
 * }
 *
 * If errors occur, output:
 * {
 *   "err":
 *   {
 *     "err_code": 1
 *     "err_msg": "xx xx"
 *   }
 * }
 * @param[in/out] out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE kr_compute_round1_3(const char *in, int in_size,
                                              char *out, int *out_size) {
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }

    std::string err_msg;

    // parse the input json string
    safeheron::mpc_snap_wasm::params::ExchangeMsgParam in_msg;
    if (!in_msg.FromJson(in, in_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // get the context
    safeheron::multi_party_ecdsa::cmp::key_recovery::Context *ctx = context_container.Find(in_msg.context_);
    if (!ctx) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Invalid context pointer.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // push message
    for (int i = 0; i < (int)in_msg.message_list_.size(); i++) {
        if (in_msg.message_list_[i].destination_ != ctx->local_party_.party_id_) {
            return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Received message is not matched with local party.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
        }
        if (!ctx->PushMessage(in_msg.message_list_[i].p2p_message_, in_msg.message_list_[i].broadcast_message_,
                              in_msg.message_list_[i].source_, in_msg.last_round_index_)) {
            err_msg = safeheron::mpc_snap_wasm::common::get_err_stack_info(ctx);
            return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
        }
    }

    // pop message and fill out the output
    safeheron::mpc_snap_wasm::params::ExchangeMsgParam out_msg;
    out_msg.context_ = std::to_string(reinterpret_cast<std::uintptr_t>(ctx));
    out_msg.current_round_index_ = ctx->get_cur_round();
    if (ctx->get_cur_round() < ctx->get_total_rounds() - 1) {
        std::vector<std::string> out_p2p_msg_arr;
        std::string out_broadcast_msg;
        std::vector<std::string> out_des_arr;
        if (!ctx->PopMessages(out_p2p_msg_arr, out_broadcast_msg, out_des_arr)) {
            return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "PopMessage failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
        }
        for (size_t i = 0; i < out_des_arr.size(); ++i) {
            safeheron::mpc_snap_wasm::params::ExchangeMsgParam::Message msg;
            msg.p2p_message_ = out_p2p_msg_arr.empty() ? std::string(): out_p2p_msg_arr[i];
            msg.broadcast_message_ = out_broadcast_msg;
            msg.destination_ = out_des_arr[i];
            msg.source_ = ctx->local_party_.party_id_;
            out_msg.message_list_.push_back(msg);
        }
    } else {
        std::string x_ki;
        ctx->x_ki_.ToHexStr(x_ki);
        uint8_t pub[65];
        std::string X_k;
        ctx->X_k_.EncodeFull(pub);
        X_k = safeheron::encode::hex::EncodeToHex(pub, 65);
        out_msg.restored_shard_ = new safeheron::mpc_snap_wasm::params::ExchangeMsgParam::RestoredShard(x_ki, X_k);
        ctx->X_.EncodeFull(pub);
        out_msg.pub_ = safeheron::encode::hex::EncodeToHex(pub, 65);
    }

    // get result in JSON string
    if (!out_msg.ToJson(out, out_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

/**
 * @brief Destroy mpc context.
 *
 * @param in JSON
 * {
 *   "context": "068824" // pointer to the context
 * }
 * @param in_size size of the input
 * @param out Null if successful
 * If errors occur, output:
 * {
 *   "err":
 *   {
 *     "err_code": 1
 *     "err_msg": "xx xx"
 *   }
 * }
 * @param out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE kr_destroy_context(const char *in, int in_size,
                                             char *out, int *out_size) {
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    nlohmann::json in_json;
    if (!safeheron::mpc_snap_wasm::common::parse_json_str(in, in_size, in_json, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string context;
    if (!json_helper::fetch_json_string_node(in_json, "context", context, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    Context *ctx = context_container.Find(context);
    delete ctx;

    context_container.Remove(context);

    return 0;
}

/**
 * @brief Aggregate partial key shards to get a complete one.
 *
 * @param[in] in JSON
 * {
 *   "curve_type": 1
 *   "partial_shards": ["E6BE16C66932FB196A2B03882A8831EA069A727996814B87741C2C97159D8CBA",
 *                      "D5B44356FFC1C6A1567B3C75115C10F80E2A2CCE2257D2A67D1C3C36991C145D"]
 *   // public key of the recovered party (X_k)
 *   "X": "0438d9427db939b1ac734fe2e95469aced65d0692f418e68d395321365f651bb00e6342042a47ef0cd3cf3d496d7aa254043e565b32906d0dbfd94450a954408fc"
 * }
 * @param in_size length of the input
 * @param out JSON (aggregated secret shard of the recovered party)
 * {
 *   //complete secret key shard of the recovered party
 *   "mnemo": "round name mansion spin equal talent action side wood tennis awful shop pattern thrive loud craft law muscle flower behind assume double leg silver"
 * }
 * If errors occur, output:
 * {
 *   "err":
 *   {
 *     "err_code": 1
 *     "err_msg": "xx xx"
 *   }
 * }
 * @param[in/out] out_size in: maximum size of the output buffer, out: actual output length
 * @return Return 0 if success, other number if failed
 */
int EMSCRIPTEN_KEEPALIVE aggregate_partial_shard(const char *in, int in_size,
                                                 char *out, int *out_size)
{
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }

    std::string err_msg;

    nlohmann::json in_json;
    if (!safeheron::mpc_snap_wasm::common::parse_json_str(in, in_size, in_json, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    int num;
    if (!json_helper::fetch_json_int_node(in_json, "curve_type", num, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }
    if (num != static_cast<int>(safeheron::curve::CurveType::SECP256K1) &&
        num != static_cast<int>(safeheron::curve::CurveType::P256) &&
        num != static_cast<int>(safeheron::curve::CurveType::ED25519)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Invalid curve type.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }
    safeheron::curve::CurveType curve_type = static_cast<safeheron::curve::CurveType>(num);
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(curve_type);

    safeheron::curve::CurvePoint X;
    if (!json_helper::fetch_json_curve_point_node(in_json, "X", curve_type, X, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }

    safeheron::bignum::BN x;
    nlohmann::json partial_shards;
    if (!json_helper::fetch_json_array_node(in_json, "partial_shards", partial_shards, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }
    for (nlohmann::json::iterator it = partial_shards.begin(); it != partial_shards.end(); ++it) {
        safeheron::bignum::BN s;
        try {
            s = safeheron::bignum::BN::FromHexStr((*it));
        } catch (std::exception &e) {
            return safeheron::mpc_snap_wasm::common::err_msg_ret(1, e.what(), __FILE__, __FUNCTION__ , __LINE__, out, out_size);
        }
        x = (x + s) % curv->n;
    }

    if (curv->g * x != X) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "The public key doesn't match the private key.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string bytes;
    x.ToBytes32BE(bytes);
    std::string mnemo;
    bool ok = safeheron::bip39::BytesToMnemonic(mnemo, bytes, safeheron::bip39::Language::ENGLISH);
    if (!ok) return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Failed to covert bytes to mnemonics.", __FILE__, __FUNCTION__, __LINE__, out, out_size);

    std::string verify_bytes;
    ok = safeheron::bip39::MnemonicToBytes(verify_bytes, mnemo, safeheron::bip39::Language::ENGLISH);
    if (!ok) return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Failed to covert mnemonics to bytes.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    if (!safeheron::multi_party_ecdsa::cmp::compare_bytes(bytes, verify_bytes)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Secondary verification of bytes to mnemonics failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    nlohmann::json out_json;
    out_json["mnemo"] = mnemo;

    if (!safeheron::mpc_snap_wasm::common::serialize_json_node(out_json, out, out_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif

