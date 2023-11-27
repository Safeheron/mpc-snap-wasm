#include <emscripten.h>
#include <vector>
#include <crypto-encode/hex.h>
#include <multi-party-ecdsa/cmp/cmp.h>
#include "params/aux_info_key_refresh_context_param.h"
#include "params/exchange_message_param.h"
#include "common/thread_safe_pointer_container.h"
#include "common/tools.h"
#include "common/global_variables.h"

#define RELEASE_OBJ(a) {if (a){delete a; a=nullptr;}}

#ifdef __cplusplus
extern "C" {
#endif

static ThreadSafePointerContainer<safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context> context_container;

/**
 * @param[in] in a JSON string
 * {
 *   "n_parties": 3
 *   "minimal_sign_key": "xx"
 *   "sid": "sid"
 *   "prepared_data": {
 *     "N": "xx"
 *     "s": "xx"
 *     "t: "xx"
 *     "p": "xx"
 *     "q": "xx"
 *     "alpha": "xx"
 *     "beta": "xx"
 *   },
 *   "update_key_shards": true
 * }
 * @param[in] in_size length of the input
 * @param[out] out a JSON string
 * {
 *   "context": "05679823"
 *   "current_round_index": 1
 *   "out_message_list":
 *   [
 *     {
 *       "p2p_message": "xx"
 *       "broadcast_message": "xx"
 *       "source": "party_1"
 *       "destination": "party_2"
 *     },
 *     {
 *       "p2p_message": "xx"
 *       "broadcast_message": "xx"
 *       "source": "party_1"
 *       "destination": "party_3"
 *     },
 *     ...
 *  ]
 * }
 * @param[in/out] out_size in: in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE mkr_create_context_compute_round0(const char *in, int in_size, char *out, int *out_size) {
    if (!get_randomness_flag()) {
        return err_msg_ret(1, "Random seed is not set!", __FILE__,__FUNCTION__, __LINE__, out, out_size);
    }

    //parse context param
    std::string err_msg;
    KeyRefreshContextParam key_refresh_context_param;
    if (!key_refresh_context_param.FromJson(in, in_size, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__,__FUNCTION__, __LINE__, out, out_size);
    }

    // create context object
    safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context *ctx = nullptr;
    if (!(ctx = new safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context(key_refresh_context_param.n_parties_))) {
        return err_msg_ret(1, "Failed to new Context.", __FILE__,__FUNCTION__, __LINE__, out, out_size);
    }

    // fill key refresh context
    bool ok = true;
    if (key_refresh_context_param.prepared_) {
        ok = safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context::CreateContext(*ctx, key_refresh_context_param.minimal_sign_key_, key_refresh_context_param.sid_, key_refresh_context_param.N_, key_refresh_context_param.s_, key_refresh_context_param.t_, key_refresh_context_param.p_, key_refresh_context_param.q_, key_refresh_context_param.alpha_, key_refresh_context_param.beta_, key_refresh_context_param.update_flag_);
    } else {
        ok = safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context::CreateContext(*ctx, key_refresh_context_param.minimal_sign_key_, key_refresh_context_param.sid_, key_refresh_context_param.update_flag_);
    }
    if (!ok) {
        RELEASE_OBJ(ctx);
        return err_msg_ret(1, "CreateContext failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // push message
    if (!ctx->PushMessage()) {
        RELEASE_OBJ(ctx)
        err_msg = get_err_stack_info(ctx);
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // pop message
    std::vector<std::string> out_p2p_msg_arr;
    std::string out_broadcast_msg;
    std::vector<std::string> out_des_arr;
    if (!ctx->PopMessages(out_p2p_msg_arr, out_broadcast_msg, out_des_arr)) {
        RELEASE_OBJ(ctx)
        return err_msg_ret(1, "PopMessage failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // fill output message
    ExchangeMsgParam out_msg;
    out_msg.context_ = (long)ctx;
    out_msg.current_round_index_ = ctx->get_cur_round();
    for (size_t i = 0; i < out_des_arr.size(); ++i) {
        ExchangeMsgParam::Message msg;
        msg.p2p_message_ = out_p2p_msg_arr.empty() ? std::string(): out_p2p_msg_arr[i];
        msg.broadcast_message_ = out_broadcast_msg;
        msg.destination_ = out_des_arr[i];
        msg.source_ = ctx->sign_key_.local_party_.party_id_;
        out_msg.message_list_.push_back(msg);
    }

    context_container.Push(ctx);

    // get the result JSON string
    if (!out_msg.ToJson(out, out_size, err_msg)) {
        RELEASE_OBJ(ctx)
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
 
    return 0;
}

/**
 *
 * @param[in] in JSON
 * {
 *   "context" : "05679823"
 *   "last_round_index": int
 *   "in_message_list":
 *   [
 *     {
 *       "p2p_message": "xx"
 *       "broadcast_message": "xx"
 *       "source": "party_1"
 *       "destination": "party_2"
 *     },
 *     {
 *       "p2p_message": "xx"
 *       "broadcast_message": "xx"
 *       "source": "party_1"
 *       "destination": "party_3"
 *     },
 *     ...
 *   ]
 * }
 * @param[in] in_size length of the input
 * @param[out] out a JSON string
 * {
 *   "context": long
 *   "current_round_index": int
 *   "out_message_list": (middle round output，null in the last round)
 *   [{
 *     "p2p_message": string
 *     "broadcast_message": string
 *     "source": string
 *     "destination": string
 *   },...]
 *   "pub": string (final round output，null in middle round)
 *   "sign_key": string
 *   "err": (null if successful)
 *   {
 *     "err_code": int
 *     "err_msg": string
 *   }
 * }
 * @param[in/out] out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE mkr_compute_round1_3(const char *in, int in_size,
                                              char *out, int *out_size) {
    if (!get_randomness_flag()) {
        return err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }

    std::string err_msg;

    // parse input json string
    ExchangeMsgParam in_msg;
    if (!in_msg.FromJson(in, in_size, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // get the context
    safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context *ctx = context_container.Find(in_msg.context_);
    if (!ctx) {
        return err_msg_ret(1, "Invalid context pointer.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // push message
    for (int i = 0; i < (int)in_msg.message_list_.size(); i++) {
        if (in_msg.message_list_[i].destination_ != ctx->sign_key_.local_party_.party_id_) {
            return err_msg_ret(1, "Received message is not matched with local party.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
        }
        if (!ctx->PushMessage(in_msg.message_list_[i].p2p_message_, in_msg.message_list_[i].broadcast_message_,
                in_msg.message_list_[i].source_, in_msg.last_round_index_)) {
            err_msg = get_err_stack_info(ctx);
            return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
        }
    }

    // pop and fill out message
    ExchangeMsgParam out_msg;
    ////
    out_msg.context_ = (long)ctx;

    out_msg.current_round_index_ = ctx->get_cur_round();
    if (ctx->get_cur_round() < ctx->get_total_rounds() - 1) {
        std::vector<std::string> out_p2p_msg_arr;
        std::string out_broadcast_msg;
        std::vector<std::string> out_des_arr;
        if (!ctx->PopMessages(out_p2p_msg_arr, out_broadcast_msg, out_des_arr)) {
            return err_msg_ret(1, "PopMessage failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
        }
        for (size_t i = 0; i < out_des_arr.size(); ++i) {
            ExchangeMsgParam::Message msg;
            msg.p2p_message_ = out_p2p_msg_arr.empty() ? std::string(): out_p2p_msg_arr[i];
            msg.broadcast_message_ = out_broadcast_msg;
            msg.destination_ = out_des_arr[i];
            msg.source_ = ctx->sign_key_.local_party_.party_id_;
            out_msg.message_list_.push_back(msg);
        }
    } else {
        std::string sign_key_base64;
        if (!ctx->sign_key_.ValidityTest() || !ctx->sign_key_.ToBase64(sign_key_base64)) {
            return err_msg_ret(1, "Sign key ToBase64 failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
        }
        uint8_t pub[65];
        ctx->sign_key_.X_.EncodeFull(pub);
        out_msg.sign_key_ = sign_key_base64;
        out_msg.pub_ = safeheron::encode::hex::EncodeToHex(pub, 65);
    }

    if (!out_msg.ToJson(out, out_size, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

int EMSCRIPTEN_KEEPALIVE mkr_destroy_context(long context) {
    context_container.Remove(context);
    return 0;
}

#ifdef __cplusplus
}
#endif