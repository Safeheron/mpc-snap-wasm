#ifndef _SIGN_PARTY_PARAM_H_
#define _SIGN_PARTY_PARAM_H_

#include <string>
#include <vector>
#include <crypto-bn/bn.h>

class SignContextParam {
public:
    bool FromJson(const char* str, int size, std::string &err_msg);
public:
    std::string sign_key_;
    safeheron::bignum::BN digest_;
    std::vector<std::string> participants_;
    std::string sid_;
};

#endif //_SIGN_PARTY_PARAM_H_