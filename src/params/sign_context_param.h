#ifndef SAFEHERON_MPC_SNAP_WASM_PARAMS_SIGN_CONTEXT_PARAM_H
#define SAFEHERON_MPC_SNAP_WASM_PARAMS_SIGN_CONTEXT_PARAM_H

#include <string>
#include <vector>
#include <crypto-bn/bn.h>

namespace safeheron {
namespace mpc_snap_wasm {
namespace params {
class SignContextParam {
public:
    bool FromJson(const char *str, int size, std::string &err_msg);
public:
    std::string sign_key_;
    safeheron::bignum::BN digest_;
    std::vector<std::string> participants_;
    std::string sid_;
};
}
}
}

#endif //SAFEHERON_MPC_SNAP_WASM_PARAMS_SIGN_CONTEXT_PARAM_H