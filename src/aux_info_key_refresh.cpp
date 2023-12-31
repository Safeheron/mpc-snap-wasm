#include <emscripten.h>
#include <vector>
#include <crypto-encode/hex.h>
#include <multi-party-ecdsa/cmp/aux_info_key_refresh/context.h>
#include "params/aux_info_key_refresh_context_param.h"
#include "params/exchange_message_param.h"
#include "common/thread_safe_pointer_container.h"
#include "common/tools.h"
#include "common/json_helper_ex.h"
#include "common/global_variables.h"

#define RELEASE_OBJ(a) {if (a){delete a; a=nullptr;}}

#ifdef __cplusplus
extern "C" {
#endif

using safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context;
static safeheron::mpc_snap_wasm::common::ThreadSafePointerContainer<safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context> context_container;

/**
 * A wrapper of third_party/multi-party-sig-cpp/src/multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh protocol
 */

/**
 * @param[in] in JSON
 * {
 *   "n_parties": 3
 *   "minimal_sign_key": "EAIYAyLeAQoKY29fc2lnbmVy...JjMDdiNzRiYjg1YTcxYzY4ZTQ2MjBkZWY4"
 *   "sid": "session_id"
 *   "prepared_data": {
 *     "N": "C269479355E6019...AA29C903A8C53736988381D7153A874F109B309E0171"
 *     "s": "7FA835F34D666D6...7191EA5C8BD6493C9B6DA4A2BBE45CBBB910A110FECF"
 *     "t": "29557C1EC62D4EA...BD4EBFD63AE7AF94EED00313766F5DA016A3A0CA7EF8"
 *     "p": "6B024DF6B38A...1D62BA86E98227"
 *     "q": "7446096AD00E...CB0361538A5371F"
 *     "alpha": "2B9DFE0EAB6BA...3D3F8152F98E2AF761E9BDEEF7FA294398236495E8"
 *     "beta": "077AA740AD281A...2820F437D317DD00D3628B42BFA8135B47AFA7734F"
 *   },
 *   "update_key_shards": true
 * }
 * @param[in] in_size length of the input
 * @param[out] out JSON
 * {
 *   "context": "069823"
 *   "current_round_index": 0
 *   "out_message_list":
 *   [
 *     {
 *       "p2p_message": "CkBiNzhjZGQ0MDBhZDY5ND...NDM1NDYzNDFiNDU2YjE0NTRjN2NmYw.."
 *       "broadcast_message": "CkBiNzhjZGQ0MDBhZDjRGQhJA...QjYzQTFFNjQ3RDNENUY0RjExNkM2N0M."
 *       "source": "party_1"
 *       "destination": "party_2"
 *     },
 *     {
 *       "p2p_message": "CkBiNzhjZGQ0MDBhZDY5YT...lGNzI5MUNBOUVBNkI3MDZDRTg5RDc3ODZD.."
 *       "broadcast_message": "CkBiNzhjZGQ0MDBhZDY5YTk...2Nzk2OUFFNzY4OTg3MDEzNTNENUY0RjExNkM2N0M."
 *       "source": "party_1"
 *       "destination": "party_3"
 *     },
 *     ...
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
 * @param[in/out] out_size in: in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE mkr_create_context_compute_round0(const char *in, int in_size, char *out, int *out_size) {
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Random seed is not set!", __FILE__,__FUNCTION__, __LINE__, out, out_size);
    }

    // parse context param
    std::string err_msg;
    safeheron::mpc_snap_wasm::params::KeyRefreshContextParam key_refresh_context_param;
    if (!key_refresh_context_param.FromJson(in, in_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__,__FUNCTION__, __LINE__, out, out_size);
    }

    // new context
    safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context *ctx = nullptr;
    if (!(ctx = new safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context(key_refresh_context_param.n_parties_))) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Failed to new Context.", __FILE__,__FUNCTION__, __LINE__, out, out_size);
    }

    // fill the context
    bool ok = true;
    if (key_refresh_context_param.prepared_) {
        ok = safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context::CreateContext(*ctx, key_refresh_context_param.minimal_sign_key_, key_refresh_context_param.sid_, key_refresh_context_param.N_, key_refresh_context_param.s_, key_refresh_context_param.t_, key_refresh_context_param.p_, key_refresh_context_param.q_, key_refresh_context_param.alpha_, key_refresh_context_param.beta_, key_refresh_context_param.update_flag_);
    } else {
        ok = safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context::CreateContext(*ctx, key_refresh_context_param.minimal_sign_key_, key_refresh_context_param.sid_, key_refresh_context_param.update_flag_);
    }
    if (!ok) {
        RELEASE_OBJ(ctx)
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "CreateContext failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // push message
    if (!ctx->PushMessage()) {
        err_msg = safeheron::mpc_snap_wasm::common::get_err_stack_info(ctx);
        RELEASE_OBJ(ctx)
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
    out_msg.current_round_index_ = ctx->get_cur_round();
    for (size_t i = 0; i < out_des_arr.size(); ++i) {
        safeheron::mpc_snap_wasm::params::ExchangeMsgParam::Message msg;
        msg.p2p_message_ = out_p2p_msg_arr.empty() ? std::string(): out_p2p_msg_arr[i];
        msg.broadcast_message_ = out_broadcast_msg;
        msg.destination_ = out_des_arr[i];
        msg.source_ = ctx->sign_key_.local_party_.party_id_;
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
 *
 * @param[in] in JSON
 * {
 *   "context" : "069823"
 *   "last_round_index": 1
 *   "in_message_list":
 *   [
 *     {
 *       "p2p_message": "CkBiNzhjZGQ0MDBhZDY5YTk3ZDVj...Y2JiNmU1NjhhZmNlOWZhNA.."
 *       "broadcast_message": "CkBiNzhjZGQ0MDBhZDY5YTk3ZDV...OTQ3YmM2YWY3YzhmN2Q5OTRiOTZlYWU0MWI."
 *       "source": "party_2"
 *       "destination": "party_1"
 *     },
 *     {
 *       "p2p_message": "CkBiNzhjZGQ0MDBhZDY5YTk3ZDVjNWQ...NjM4ZDZhMjdlNGFiNWZjOGJlYWI2YzE."
 *       "broadcast_message": "CkBiNzhjZGQ0MDBhZDY5YTk3ZDVjNWQ0YzE3NTZj...NEYwQTc0RDYzNkI0QkI5NUE4QkQ."
 *       "source": "party_3"
 *       "destination": "party_1"
 *     },
 *     ...
 *   ]
 * }
 * @param[in] in_size length of the input
 * @param[out] out JSON
 * Middle round output:
 * {
 *   "context": "069823"
 *   "current_round_index": 2
 *   "out_message_list":
 *   [
 *     {
 *       "p2p_message": "CkBiNzhjZGQ0MDBhZDY5ND...NDM1NDYzNDFiNDU2YjE0NTRjN2NmYw.."
 *       "broadcast_message": "CkBiNzhjZGQ0MDBhZDjRGQhJA...QjYzQTFFNjQ3RDNENUY0RjExNkM2N0M."
 *       "source": "party_1"
 *       "destination": "party_2"
 *     },
 *     {
 *       "p2p_message": "CkBiNzhjZGQ0MDBhZDY5YT...lGNzI5MUNBOUVBNkI3MDZDRTg5RDc3ODZD.."
 *       "broadcast_message": "CkBiNzhjZGQ0MDBhZDY5YTk...2Nzk2OUFFNzY4OTg3MDEzNTNENUY0RjExNkM2N0M."
 *       "source": "party_1"
 *       "destination": "party_3"
 *     },
 *     ...
 *   ]
 * }
 * Final round output:
 * {
 *   "pub": "04df7a386d994c8e37afeddfe73e6e66ba22b7a56d7c555534c25e43eed7bc773c188e84654f8f7eb8ce526fbc7e77a7237dcc41ca8ba9bb4e26cadec633d47275"
 *   "sign_key": "EAIYAyKEGwoKY29fc2l...ViYWVhY2JmZTEwYmU4MDkyN2RhMzAyYmZjMzVkOTlkOWU4ZmJhNTY5ZGZiMDNmZDFlMzY3MTMyZjNkZg.."
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
int EMSCRIPTEN_KEEPALIVE mkr_compute_round1_3(const char *in, int in_size,
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
    safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context *ctx = context_container.Find(in_msg.context_);
    if (!ctx) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Invalid context pointer.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // push message
    for (int i = 0; i < (int)in_msg.message_list_.size(); i++) {
        if (in_msg.message_list_[i].destination_ != ctx->sign_key_.local_party_.party_id_) {
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
            msg.source_ = ctx->sign_key_.local_party_.party_id_;
            out_msg.message_list_.push_back(msg);
        }
    } else {
        std::string sign_key_base64;
        if (!ctx->sign_key_.ValidityTest() || !ctx->sign_key_.ToBase64(sign_key_base64)) {
            return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Sign key ToBase64 failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
        }
        uint8_t pub[65];
        ctx->sign_key_.X_.EncodeFull(pub);
        out_msg.sign_key_ = sign_key_base64;
        out_msg.pub_ = safeheron::encode::hex::EncodeToHex(pub, 65);
    }

    // get the result JSON string
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
 *   "context": "069823" // pointer to the context
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
int EMSCRIPTEN_KEEPALIVE mkr_destroy_context(const char *in, int in_size,
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
    context_container.Remove(context);
    RELEASE_OBJ(ctx)

    return 0;
}

#ifdef __cplusplus
}
#endif