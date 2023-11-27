#ifndef SAFEHERONMULTIPARTYSIGNATURE_KEY_GEN_CONTEXT_PARAM_H
#define SAFEHERONMULTIPARTYSIGNATURE_KEY_GEN_CONTEXT_PARAM_H

#include <string>
#include <vector>
#include <crypto-bn/bn.h>
#include <crypto-curve/curve.h>

class KeyGenContextParam {
public:
    bool FromJson(const char *str, int size, std::string &err_msg);
public:
    KeyGenContextParam();

public:
    safeheron::curve::CurveType curve_type_;
    int n_parties_;
    int threshold_;
    std::string party_id_;
    safeheron::bignum::BN index_;
    std::vector<std::string> remote_party_id_arr_;
    std::vector<safeheron::bignum::BN> remote_party_index_arr_;
    std::string sid_;

    bool prepared_;
    safeheron::bignum::BN N_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN t_;
    safeheron::bignum::BN p_;
    safeheron::bignum::BN q_;
    safeheron::bignum::BN alpha_;
    safeheron::bignum::BN beta_;
};

#endif //SAFEHERONMULTIPARTYSIGNATURE_KEY_GEN_CONTEXT_PARAM_H
