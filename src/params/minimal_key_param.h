#ifndef SAFEHERON_PROJECTS_MPC_CMP_PARAMS_MINIMAL_KEY_PARAM_H
#define SAFEHERON_PROJECTS_MPC_CMP_PARAMS_MINIMAL_KEY_PARAM_H

#include <string>
#include <vector>
#include <crypto-bn/bn.h>
#include <crypto-curve/curve.h>
#include <crypto-curve/curve_point.h>

class MinimalKeyParam {
public:
    MinimalKeyParam();
public:
    bool FromJson(const char* str, int size, std::string &err_msg);
    std::string gen_rid();
public:
    safeheron::curve::CurveType curve_type_;
    int n_parties_;
    int threshold_;
    std::string party_id_;
    safeheron::bignum::BN index_;
    safeheron::bignum::BN x_;
    safeheron::curve::CurvePoint X_;
    std::vector<std::string> remote_party_id_arr_;
    std::vector<safeheron::bignum::BN> remote_party_index_arr_;
    std::vector<safeheron::curve::CurvePoint> remote_X_arr_;
};

#endif //SAFEHERON_PROJECTS_MPC_CMP_PARAMS_MINIMAL_KEY_PARAM_H