#ifndef SAFEHERON_MPC_SNAP_WASM_PARAMS_MINIMAL_KEY_GEN_CONTEXT_PARAM_H
#define SAFEHERON_MPC_SNAP_WASM_PARAMS_MINIMAL_KEY_GEN_CONTEXT_PARAM_H

#include <string>
#include <vector>
#include <crypto-bn/bn.h>
#include <crypto-curve/curve.h>

namespace safeheron {
namespace mpc_snap_wasm {
namespace params {
class MinimalKeyGenContextParam {
public:
    bool FromJson(const char *str, int size, std::string &err_msg);
public:
    MinimalKeyGenContextParam();

public:
    safeheron::curve::CurveType curve_type_;
    int n_parties_;
    int threshold_;
    std::string party_id_;
    safeheron::bignum::BN index_;
    std::string sid_;
    std::vector<std::string> remote_party_id_arr_;
    std::vector<safeheron::bignum::BN> remote_party_index_arr_;
};
}
}
}

#endif //SAFEHERON_MPC_SNAP_WASM_PARAMS_MINIMAL_KEY_GEN_CONTEXT_PARAM_H