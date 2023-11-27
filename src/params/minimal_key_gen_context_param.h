#ifndef _KEY_GEN_PARTY_PARAM_H_
#define _KEY_GEN_PARTY_PARAM_H_

#include <string>
#include <vector>
#include <crypto-bn/bn.h>
#include <crypto-curve/curve.h>

class MinimalKeyGenContextParam {
public:
    bool FromJson(const char* str, int size, std::string &err_msg);
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

#endif //_KEY_GEN_PARTY_PARAM_H_