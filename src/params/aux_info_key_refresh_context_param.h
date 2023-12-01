#ifndef SAFEHERON_MPC_SNAP_WASM_PARAMS_AUX_INFO_KEY_REFRESH_CONTEXT_PARAM_H
#define SAFEHERON_MPC_SNAP_WASM_PARAMS_AUX_INFO_KEY_REFRESH_CONTEXT_PARAM_H

#include <string>
#include <crypto-bn/bn.h>
#include <multi-party-ecdsa/cmp/minimal_sign_key.h>

namespace safeheron {
namespace mpc_snap_wasm {
namespace params {
class KeyRefreshContextParam {
public:
    bool FromJson(const char *str, int size, std::string &err_msg);
public:
    KeyRefreshContextParam();

public:
    int n_parties_;
    safeheron::multi_party_ecdsa::cmp::MinimalSignKey minimal_sign_key_;
    std::string sid_;
    bool update_flag_;

    bool prepared_;
    safeheron::bignum::BN N_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN t_;
    safeheron::bignum::BN p_;
    safeheron::bignum::BN q_;
    safeheron::bignum::BN alpha_;
    safeheron::bignum::BN beta_;
};
}
}
}
#endif //SAFEHERON_MPC_SNAP_WASM_PARAMS_AUX_INFO_KEY_REFRESH_CONTEXT_PARAM_H