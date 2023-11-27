#ifndef SAFEHERONMULTIPARTYSIGNATURE_KEY_RECOVERY_CONTEXT_PARAM_H
#define SAFEHERONMULTIPARTYSIGNATURE_KEY_RECOVERY_CONTEXT_PARAM_H

#include <string>
#include <crypto-bn/bn.h>
#include <crypto-curve/curve.h>

class KeyRecoveryContextParam {
public:
    KeyRecoveryContextParam();
public:
    bool FromJson(const char *str, int size, std::string &err_msg);
public:
    safeheron::curve::CurveType curve_type_;
    safeheron::bignum::BN x_;
    safeheron::bignum::BN i_;
    safeheron::bignum::BN j_;
    safeheron::bignum::BN k_;
    std::string local_party_id_;
    std::string remote_party_id_;
};

#endif //SAFEHERONMULTIPARTYSIGNATURE_KEY_RECOVERY_CONTEXT_PARAM_H
