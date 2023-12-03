#include <emscripten.h>
#include <vector>
#include <crypto-encode/hex.h>
#include <multi-party-ecdsa/cmp/minimal_key_gen/context.h>
#include "params/minimal_key_gen_context_param.h"
#include "params/exchange_message_param.h"
#include "common/thread_safe_pointer_container.h"
#include "common/tools.h"
#include "common/json_helper_ex.h"
#include "common/global_variables.h"

#define RELEASE_OBJ(a) {if (a){delete a; a=nullptr;}}

#ifdef __cplusplus
extern "C" {
#endif

using safeheron::multi_party_ecdsa::cmp::minimal_key_gen::Context;
static safeheron::mpc_snap_wasm::common::ThreadSafePointerContainer<safeheron::multi_party_ecdsa::cmp::minimal_key_gen::Context> context_container;

/**
 * A wrapper of third_party/multi-party-sig-cpp/src/multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen protocol
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
 *   "n_parties": 3
 *   "threshold": 2
 *   "party_id": "party_1"
 *   "index": "1"
 *   "remote_parties": [
 *     {
 *       "party_id": "party_2"
 *       "index": "2"
 *     },
 *     {
 *       "party_id": "party_3"
 *       "index": "3"
 *     },
 *     ...
 *   ]
 *   "sid": "session_id"
 * }
 * @param[in] in_size length of the input
 * @param[out] out JSON
 * {
 *   "context": "213216"
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
 * @param[in/out] out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE mkg_create_context_compute_round0(const char* in, int in_size,
                                                           char* out, int* out_size) {
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }

    std::string err_msg;

    // parse the input json string
    safeheron::mpc_snap_wasm::params::MinimalKeyGenContextParam minimal_key_gen_context_param;
    if (!minimal_key_gen_context_param.FromJson(in, in_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }

    // new context
    safeheron::multi_party_ecdsa::cmp::minimal_key_gen::Context *ctx = nullptr;
    if (!(ctx = new safeheron::multi_party_ecdsa::cmp::minimal_key_gen::Context(minimal_key_gen_context_param.n_parties_))) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Failed to new Context.", __FILE__,__FUNCTION__, __LINE__, out, out_size);
    }

    // fill the context
    if (!safeheron::multi_party_ecdsa::cmp::minimal_key_gen::Context::CreateContext(*ctx, minimal_key_gen_context_param.curve_type_, minimal_key_gen_context_param.threshold_, minimal_key_gen_context_param.n_parties_, minimal_key_gen_context_param.index_,
                                                      minimal_key_gen_context_param.party_id_, minimal_key_gen_context_param.remote_party_index_arr_, minimal_key_gen_context_param.remote_party_id_arr_, minimal_key_gen_context_param.sid_)) {
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
        msg.source_ = ctx->minimal_sign_key_.local_party_.party_id_;
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
 *   "context" : "213216"
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
 *   "context": "213216"
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
 *   "minimal_sign_key": "EAIYAyLeAQoKY29fc2lnbmVy...JjMDdiNzRiYjg1YTcxYzY4ZTQ2MjBkZWY4"
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
int EMSCRIPTEN_KEEPALIVE mkg_compute_round1_3 (const char* in, int in_size,
                                              char* out, int* out_size) {
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Required to set a user seed for openssl random generator.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }

    std::string err_msg;

    // parse the input json string
    safeheron::mpc_snap_wasm::params::ExchangeMsgParam in_msg;
    if (!in_msg.FromJson(in, in_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // get the context
    safeheron::multi_party_ecdsa::cmp::minimal_key_gen::Context *ctx = context_container.Find(in_msg.context_);
    if (!ctx) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Invalid context pointer.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    // push message
    for (int i = 0; i < (int)in_msg.message_list_.size(); i++) {
        if (in_msg.message_list_[i].destination_ != ctx->minimal_sign_key_.local_party_.party_id_) {
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
            msg.source_ = ctx->minimal_sign_key_.local_party_.party_id_;
            out_msg.message_list_.push_back(msg);
        }
    } else {
        std::string minimal_sign_key_base64;
        if (!ctx->minimal_sign_key_.ValidityTest() || 
            !ctx->minimal_sign_key_.ToBase64(minimal_sign_key_base64)) {
            return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Minimal sign key ToBase64 failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
        }
        uint8_t pub[65];
        ctx->minimal_sign_key_.X_.EncodeFull(pub);
        out_msg.minimal_sign_key_ = minimal_sign_key_base64;
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
int EMSCRIPTEN_KEEPALIVE mkg_destroy_context(const char *in, int in_size,
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