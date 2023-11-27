#include <emscripten.h>
#include <vector>
#include <multi-party-ecdsa/cmp/cmp.h>
#include <multi-party-ecdsa/cmp/key_recovery/context.h>
#include <crypto-encode/hex.h>
#include <crypto-bip39/bip39.h>
#include "params/key_recovery_context_param.h"
#include "params/exchange_message_param.h"
#include "common/thread_safe_pointer_container.h"
#include "common/tools.h"
#include "common/global_variables.h"

#define RELEASE_OBJ(a) {if (a){delete a; a=nullptr;}}

#ifdef __cplusplus
extern "C" {
#endif

static ThreadSafePointerContainer<safeheron::multi_party_ecdsa::cmp::key_recovery::Context> context_container;

/**
 * 2-3 key recovery protocol
 */

/**
 * Curve type
 * - 1: SECP256K1
 * - 2: P256
 * - 2^5: ED25519
 */
/**
 * @param[in] in json str of input
 * {
 * "curve_type": int
 * "mnemo": string (local secret key shard)
 * "i": string (local party index)
 * "j": string (remote party index (no lost key))
 * "k": string (the third party index (lost key))
 * "local_party_id": string
 * "remote_party_id": string
 * }
 * @param[in] in_size length of the input
 * @param[out] out json str of output
 * {
 * "context": long
 * "current_round_index": int
 * "out_message_list":
 * [{
 * "p2p_message": string
 * "broadcast_message": string
 * "source": string
 * "destination": string
 * },...]
 * "err": (null if successful)
 * {
 * "err_code": int
 * "err_msg": string
 * }
 * }
 * @param[in/out] out_size in: maximum size of the output buffer, out: actual output length
 * @return Return 0 if success, other number if failed
 */
int EMSCRIPTEN_KEEPALIVE kr_create_context_compute_round0(const char *in, int in_size,
                                                          char *out, int *out_size) {
    if (!get_RandomSeedFlag()) {
        return err_msg_ret(1, "Required to set a user seed for openssl random generator.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }

    const int N_PARTIES = 2;

    KeyRecoveryContextParam key_recovery_context_param;
    if (!key_recovery_context_param.FromJson(in, in_size)) {
        return err_msg_ret(key_recovery_context_param.err_code_, key_recovery_context_param.err_msg_, out, out_size);
    }

    // create context
    safeheron::multi_party_ecdsa::cmp::key_recovery::Context *ctx = nullptr;
    if (!(ctx = new safeheron::multi_party_ecdsa::cmp::key_recovery::Context(N_PARTIES))) {
        return err_msg_ret(1, "cmp::key_recovery::Context, new Context return null.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // fill key_gen context
    bool ok = safeheron::multi_party_ecdsa::cmp::key_recovery::Context::CreateContext(*ctx, key_recovery_context_param.curve_type_, key_recovery_context_param.x_, key_recovery_context_param.i_, key_recovery_context_param.j_, key_recovery_context_param.k_, key_recovery_context_param.local_party_id_, key_recovery_context_param.remote_party_id_);
    if (!ok) {
        RELEASE_OBJ(ctx)
        return err_msg_ret(1, "cmp::key_recovery: failed to create context.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // push message
    if (!ctx->PushMessage()) {
        RELEASE_OBJ(ctx)
        std::string err_msg = assemble_err_msg("cmp::key_recovery: failed to push message.", __FILE__, __FUNCTION__, __LINE__);
        err_msg += get_err_stack_info(ctx);
        return err_msg_ret(1, err_msg, out, out_size);
    }

    // pop message
    std::vector<std::string> out_p2p_msg_arr;
    std::string out_broadcast_msg;
    std::vector<std::string> out_des_arr;
    if (!ctx->PopMessages(out_p2p_msg_arr, out_broadcast_msg, out_des_arr)) {
        RELEASE_OBJ(ctx)
        std::string err_msg = assemble_err_msg("cmp::key_recovery: failed to pop message.", __FILE__, __FUNCTION__, __LINE__);
        err_msg += get_err_stack_info(ctx);
        return err_msg_ret(1, err_msg, out, out_size);
    }

    // fill out put message
    ExchangeMsgParam out_msg;
    out_msg.context_ = (long)ctx;
    out_msg.current_round_index_ = 0;
    for (size_t i = 0; i < out_des_arr.size(); ++i) {
        ExchangeMsgParam::message msg;
        msg.p2p_message = out_p2p_msg_arr.empty() ? std::string(): out_p2p_msg_arr[i];
        msg.broadcast_message = out_broadcast_msg;
        msg.destination = out_des_arr[i];
        msg.source = ctx->local_party_.party_id_;
        out_msg.message_list_.push_back(msg);
    }

    // get the result JSON string
    if (!out_msg.ToJson(out, out_size)) {
        RELEASE_OBJ(ctx)
        return err_msg_ret(out_msg.err_code_, out_msg.err_msg_, out, out_size);
    }

    // save context object
    context_container.Push(ctx);

    return 0;
}

/**
 * @param[in] in json str of input
 * {
 * "context" : long
 * "last_round_index": int
 * "in_message_list":
 * [{
 * "p2p_message": string
 * "broadcast_message": string
 * "source": string
 * "destination": string
 * },...]
 * }
 * @param[in] in_size length of the input
 * @param[out] out json str of output
 * {
 * "context": long
 * "current_round_index": int
 * "out_message_list": (middle round output，null in the last round)
 * [{
 * "p2p_message": string
 * "broadcast_message": string
 * "source": string
 * "destination": string
 * },...]
 * "s": string (partial secret key shard of the third party)
 * "X_k": string (public key shard of the third party)
 * "pub": string (full public key)
 * "err": (null if successful)
 * {
 * "err_code": int
 * "err_msg": string
 * }
 * }
 * @param[in/out] out_size in: maximum size of the output buffer, out: actual output length
 * @return Return 0 if success, other number if failed
 */
int EMSCRIPTEN_KEEPALIVE kr_compute_round1_3(const char *in, int in_size,
                                              char *out, int *out_size) {
    if (!get_RandomSeedFlag()) {
        return err_msg_ret(1, "Required to set a user seed for openssl random generator.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }

    // parse input json string
    ExchangeMsgParam in_msg(true);
    if (!in_msg.FromJson(in, in_size)) {
        return err_msg_ret(in_msg.err_code_, in_msg.err_msg_, out, out_size);
    }

    // get the context
    safeheron::multi_party_ecdsa::cmp::key_recovery::Context *ctx = context_container.Find(in_msg.context_);
    if (!ctx) {
        return err_msg_ret(1, "Invalid context pointer.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // push message
    for (int i = 0; i < (int)in_msg.message_list_.size(); i++) {
        if (in_msg.message_list_[i].destination != ctx->local_party_.party_id_) {
            return err_msg_ret(1, "Received message is not matched with local party.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
        }
        if (!ctx->PushMessage(in_msg.message_list_[i].p2p_message, in_msg.message_list_[i].broadcast_message,
                              in_msg.message_list_[i].source, in_msg.last_round_index_)) {
            std::string err_msg = assemble_err_msg("cmp::key_recovery: failed to push message", __FILE__, __FUNCTION__, __LINE__);
            err_msg += get_err_stack_info(ctx);
            return err_msg_ret(1, err_msg, out, out_size);
        }
    }

    // pop and fill out message
    ExchangeMsgParam out_msg;
    out_msg.context_ = (long)ctx;
    out_msg.current_round_index_ = in_msg.last_round_index_ + 1;
    if (in_msg.last_round_index_ < 2) {
        std::vector<std::string> out_p2p_msg_arr;
        std::string out_broadcast_msg;
        std::vector<std::string> out_des_arr;
        if (!ctx->PopMessages(out_p2p_msg_arr, out_broadcast_msg, out_des_arr)) {
            std::string err_msg = assemble_err_msg("cmp::key_recovery: failed to pop message.", __FILE__, __FUNCTION__, __LINE__);
            err_msg += get_err_stack_info(ctx);
            return err_msg_ret(1, err_msg, out, out_size);
        }
        for (size_t i = 0; i < out_des_arr.size(); ++i) {
            ExchangeMsgParam::message msg;
            msg.p2p_message = out_p2p_msg_arr.empty() ? std::string(): out_p2p_msg_arr[i];
            msg.broadcast_message = out_broadcast_msg;
            msg.destination = out_des_arr[i];
            msg.source = ctx->local_party_.party_id_;
            out_msg.message_list_.push_back(msg);
        }
    }
    else {
        std::string s;
        ctx->s_.ToHexStr(s);
        std::string pub_hex;
        uint8_t encoded_pub[65];
        ctx->X_k_.EncodeFull(encoded_pub);
        pub_hex = safeheron::encode::hex::EncodeToHex(encoded_pub, 65);
        out_msg.shard_ = new ExchangeMsgParam::RestoredShard(s, pub_hex);
        ctx->pub_.EncodeFull(encoded_pub);
        pub_hex = safeheron::encode::hex::EncodeToHex(encoded_pub, 65);
        out_msg.pub_ = pub_hex;
    }

    // get result in JSON string
    if (!out_msg.ToJson(out, out_size)) {
        return err_msg_ret(out_msg.err_code_, out_msg.err_msg_, out, out_size);
    }

    return 0;
}

int EMSCRIPTEN_KEEPALIVE kr_destroy_context(long context) {
    context_container.Remove(context);
    return 0;
}

int EMSCRIPTEN_KEEPALIVE kr_destroy() {
    context_container.Clear();
    return 0;
}

/**
 * Aggregate to get a complete shard
 * @param[in] in json str of input
 * {
 * "curve_type": int
 * "X": string (third party pub key)
 * "partial_shards": [] (The length must be 2)
 * }
 * @param in_size length of the input
 * @param out json str of output
 * {
 * "mnemo": string (aggregated secret shard of the third party)
 * "err": (null if successful)
 * {
 * "err_code": int
 * "err_msg": string
 * }
 * }
 * @param[in/out] out_size in: maximum size of the output buffer, out: actual output length
 * @return Return 0 if success, other number if failed
 */
int EMSCRIPTEN_KEEPALIVE aggregate_partial_shard(const char *in, int in_size,
                                                 char *out, int *out_size)
{
    //in_check
    if (!get_RandomSeedFlag()) {
        return err_msg_ret(1, "Required to set a user seed for openssl random generator.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    int err_code;
    std::string err_msg;

    nlohmann::json in_json;
    if (!json_parse(in, in_size, in_json, err_code, err_msg, __FILE__, __FUNCTION__, __LINE__)) {
        return err_msg_ret(err_code, err_msg, out, out_size);
    }

    if (in_json.find("curve_type") == in_json.end()) {
        return err_msg_ret(1, "Invalid json. Required field 'curve_type' does not exist.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
    if (!in_json["curve_type"].is_number()) {
        return err_msg_ret(1, "Invalid json. The field 'curve_type' is not a number.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    int curve_type = in_json["curve_type"];
    if (curve_type != 1 && curve_type != 2 && curve_type != 32) {
        return err_msg_ret(1, "Invalid curve type.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }
    safeheron::curve::CurveType curve_t = static_cast<safeheron::curve::CurveType>(curve_type);
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(curve_t);

    safeheron::curve::CurvePoint X;
    if (in_json.find("X") == in_json.end()) {
        return err_msg_ret(1, "Invalid json. Required field 'X' does not exist.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
    if (!in_json["X"].is_string()) {
        return err_msg_ret(1, "Invalid json. The field 'X' is not a string.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
    if (!encoded_pub_parse(in_json["X"], curve_t, X, err_code, err_msg, __FILE__, __FUNCTION__, __LINE__)) {
        return err_msg_ret(err_code, err_msg, out, out_size);
    }

    if (in_json.find("partial_shards") == in_json.end()) {
        return err_msg_ret(1, "Invalid json. Required field 'partial_shards' does not exist.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
    if (!in_json["partial_shards"].is_array() || in_json["partial_shards"].size() != 2) {
        return err_msg_ret(1, "Invalid json. The field 'partial_shards' is not an array of length 2.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
    safeheron::bignum::BN x;
    nlohmann::json partial_shards = in_json["partial_shards"];
    for (nlohmann::json::iterator it = partial_shards.begin(); it != partial_shards.end(); ++it) {
        safeheron::bignum::BN s;
        if (!(*it).is_string()) {
            return err_msg_ret(1, "Invalid json. The field in 'partial_shards' is not a string.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
        }
        if (!hex2BN(*it, s, err_code, err_msg, __FILE__, __FUNCTION__, __LINE__)) {
            return err_msg_ret(err_code, err_msg, out, out_size);
        }
        x = (x + s) % curv->n;
    }

    if (curv->g * x != X) {
        return err_msg_ret(1, "The private key and public key do not match.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string bytes;
    x.ToBytes32BE(bytes);
    std::string mnemo;
    bool ok = safeheron::bip39::BytesToMnemonic(mnemo, bytes, safeheron::bip39::Language::ENGLISH);
    if (!ok) return err_msg_ret(1, "Bytes to mnemonic conversion failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);

    nlohmann::json out_json;
    out_json["mnemo"] = mnemo;

    if (!json_ser(out_json, out, out_size, err_code, err_msg, __FILE__, __FUNCTION__, __LINE__)) {
        return err_msg_ret(err_code, err_msg, out, out_size);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif

