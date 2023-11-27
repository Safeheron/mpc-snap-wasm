#include <emscripten.h>
#include <vector>
#include <multi-party-ecdsa/cmp/minimal_sign_key.h>
#include <multi-party-ecdsa/cmp/sign_key.h>
#include <multi-party-ecdsa/cmp/util.h>

#include <crypto-bn/bn.h>
#include <openssl/rand.h>
#include <crypto-bn/rand.h>
#include <crypto-encode/hex.h>
#include <crypto-curve/curve.h>
#include <crypto-curve/curve_type.h>
#include <crypto-curve/curve_point.h>
#include <crypto-bip39/bip39.h>
#include <crypto-ecies/auth_enc.h>
#include <crypto-sss/polynomial.h>

#include "third_party/nlohmann/json.hpp"
#include "params/minimal_key_param.h"
#include "common/tools.h"
#include "common/json_helper_ex.h"
#include "common/global_variables.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Set randomness for openssl.
 *
 * @param[in] seed : Bytes of a random seed  .
 * @param[in] size : Size of the bytes.
 * @return : Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE SetSeed(uint8_t* seed, int size)
{
    const int MIN_SEED_LEN = 1024;

    if (size < MIN_SEED_LEN || !seed) {
        return -1;
    }

    RAND_seed(seed, size);
    set_randomness_flag();
    return 0;
}

/**
 * @brief Create a random number and return it as bytes.
 *
 * @param[in] size : Size of the random number, in bytes.
 * @param[out] num : Output buffer to hold the random bytes.
 * @return : Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE randNum(int size, uint8_t* num)
{
    if (!get_randomness_flag()) {
        return -1;
    }
    if (size <= 0 || !num) {
        return -1;
    }

    safeheron::rand::RandomBytes(num, size);

    return 0;
}

/**
 * @brief Generate private key and corresponding public key on specific curve.
 *
 * @param[in] curve_type specific elliptic curve
 * - 1 represents Secp256k1
 * - 2 represents P256
 * - 2^5 represents ED25519
 * @param[out] out a JSON string
 * {
 *   "priv": "private key encoded as a hex string"
 *   "pub": "public key, full encoding in 65 bytes, and encoded as a hex string"
 *   "err": (null if successful)
 *   {
 *     "err_code": 1
 *     "err_msg": "xx"
 *   }
 * }
 * @param[in/out] out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE generate_key_pair(int curve_type, char *out, int *out_size) {
    if (!get_randomness_flag()) {
        return err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }

    if (curve_type != static_cast<int>(safeheron::curve::CurveType::SECP256K1) &&
        curve_type != static_cast<int>(safeheron::curve::CurveType::P256) &&
        curve_type != static_cast<int>(safeheron::curve::CurveType::ED25519)) {
        return err_msg_ret(1, "Invalid curve type.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(static_cast<safeheron::curve::CurveType>(curve_type));
    safeheron::bignum::BN priv = safeheron::rand::RandomBNLt(curv->n);
    safeheron::curve::CurvePoint pub = curv->g * priv;

    nlohmann::json out_json;
    std::string str;
    priv.ToHexStr(str);
    out_json["priv"] = str;
    uint8_t encoded_pub[65];
    pub.EncodeFull(encoded_pub);
    str = safeheron::encode::hex::EncodeToHex(encoded_pub, 65);
    out_json["pub"] = str;

    std::string err_msg;
    if (!serialize_json_node(out_json, out, out_size, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

/**
 * @brief Encryption with ECIES algorithm
 *
 * @param[in] in a JSON string
 * {
 *   "local_priv": "private key encoded as a hex string"
 *   "remote_pub": "remote party's public key, full encoding in 65 bytes, and encoded as a hex string"
 *   "plain": "xx"
 * }
 * @param[in] in_size length of the input
 * @param[out] out a JSON string
 * {
 *   "cypher": "xx"
 *   "err": (null if successful)
 *   {
 *     "err_code": 1
 *     "err_msg": "xx"
 * }
 * }
 * @param[in/out] out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE AuthEnc_encrypt(const char *in, int in_size, char *out, int *out_size) {
    if (!get_randomness_flag()) {
        return err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    nlohmann::json in_json;
    if (!parse_json_str(in, in_size, in_json, err_msg)) {
        return err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::bignum::BN local_priv;
    if (!json_helper::fetch_json_bn_node(in_json, "local_priv", local_priv, err_msg)) {
        return err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::curve::CurvePoint remote_pub;
    if (!json_helper::fetch_json_curve_point_node(in_json, "remote_pub", safeheron::curve::CurveType::P256, remote_pub, err_msg)) {
        return err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string plain;
    if (!json_helper::fetch_json_string_node(in_json, "plain", plain, err_msg)) {
        return err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::ecies::AuthEnc enc;
    std::string cypher;
    bool ok = enc.Encrypt(local_priv, remote_pub, plain, cypher);
    if (!ok) return err_msg_ret(1, "AuthEnc: encryption failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    std::string cypher_hex = safeheron::encode::hex::EncodeToHex(cypher);

    nlohmann::json out_json;
    out_json["cypher"] = cypher_hex;

    if (!serialize_json_node(out_json, out, out_size, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

/**
 * @brief ECIES Decryption
 *
 * @param[in] in a JSON string
 * {
 *   "local_priv": "private key encoded as a hex string"
 *   "remote_pub": "remote party's public key, full encoding in 65 bytes, and encoded as a hex string"
 *   "cypher": "xx"
 * }
 * @param[in] in_size length of the input
 * @param[out] out a JSON string
 * {
 *   "plain": "xx"
 *   "err": (null if successful)
 *   {
 *     "err_code": 1
 *     "err_msg": "xx"
 *   }
 * }
 * @param[in/out] out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE AuthEnc_decrypt(const char *in, int in_size, char *out, int *out_size) {
    if (!get_randomness_flag()) {
        return err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    nlohmann::json in_json;
    if (!parse_json_str(in, in_size, in_json, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::bignum::BN local_priv;
    if (!json_helper::fetch_json_bn_node(in_json, "local_priv", local_priv, err_msg)) {
        return err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::curve::CurvePoint remote_pub;
    if (!json_helper::fetch_json_curve_point_node(in_json, "remote_pub", safeheron::curve::CurveType::P256, remote_pub, err_msg)) {
        return err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string cypher;
    if (!json_helper::fetch_json_string_node(in_json, "cypher", cypher, err_msg)) {
        return err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::ecies::AuthEnc enc;
    std::string plain;
    bool ok = enc.Decrypt(local_priv, remote_pub, cypher, plain);
    if (!ok) return err_msg_ret(1, "AuthEnc: decryption failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);

    nlohmann::json out_json;
    out_json["plain"] = plain;

    if (!serialize_json_node(out_json, out, out_size, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

/**
 * @brief ECDSA signature algorithm.
 *
 * @param[in] in a JSON string
 * {
 *   "priv": "private key encoded as a hex string"
 *   "digest": "digest to be signed, encoded as a hex string"
 * }
 * @param[in] in_size length of the input
 * @param[out] out a JSON string
 * {
 *   "sig": "signature of the digest, encoded as a hex string"
 *   "err": (null if successful)
 *   {
 *     "err_code": 1
 *     "err_msg": "xx"
 *   }
 * }
 * @param[in/out] out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE ecdsa_sign(const char *in, int in_size, char *out, int *out_size) {
    if (!get_randomness_flag()) {
        return err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    const size_t DIGEST_SIZE = 32;
    const size_t SIG_SIZE = 64;

    nlohmann::json in_json;
    if (!parse_json_str(in, in_size, in_json, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::bignum::BN priv;
    if (!json_helper::fetch_json_bn_node(in_json, "priv", priv, err_msg)) {
        return err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string digest_bytes;
    if (!json_helper::fetch_json_bytes_node(in_json, "digest", digest_bytes, err_msg)) {
        return err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
    uint8_t digest[DIGEST_SIZE] = {0};
    memcpy(digest, digest_bytes.c_str(), digest_bytes.length());

    uint8_t sig[SIG_SIZE];
    safeheron::curve::ecdsa::Sign(safeheron::curve::CurveType::P256, priv, digest, sig);
    std::string sig_hex = safeheron::encode::hex::EncodeToHex(sig, SIG_SIZE);

    nlohmann::json out_json;
    out_json["sig"] = sig_hex;

    if (!serialize_json_node(out_json, out, out_size, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

/**
 * @brief ECDSA signature verification algorithm.
 *
 * @param[in] in a JSON string
 * {
 *   "pub": "public key, full encoding in 65 bytes, and encoded as a hex string"
 *   "digest": "digest to be signed, encoded as a hex string"
 *   "sig": "signature of the digest, encoded as a hex string"
 * }
 * @param[in] in_size length of the input
 * @param[out] out null if successful
 * Or :
 * {
 *   "err":
 *   {
 *     "err_code": 1
 *     "err_msg": "xx"
 *   }
 * }
 * @param[in/out] out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE ecdsa_verify(const char *in, int in_size, char *out, int *out_size) {
    if (!get_randomness_flag()) {
        return err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    const size_t DIGEST_SIZE = 32;
    const size_t SIG_SIZE = 64;

    nlohmann::json in_json;
    if (!parse_json_str(in, in_size, in_json, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::curve::CurvePoint pub;
    if (!json_helper::fetch_json_curve_point_node(in_json, "pub", safeheron::curve::CurveType::P256, pub, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string digest_bytes;
    if (!json_helper::fetch_json_bytes_node(in_json, "digest", digest_bytes, err_msg)) {
        return err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
    uint8_t digest[DIGEST_SIZE] = {0};
    memcpy(digest, digest_bytes.c_str(), digest_bytes.length());

    std::string sig;
    if (!json_helper::fetch_json_bytes_node(in_json, "sig", sig, err_msg)) {
        return err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
    if (sig.length() != SIG_SIZE) {
        return err_msg_ret(1, "The length of the signature is invalid.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }

    bool ok = safeheron::curve::ecdsa::Verify(safeheron::curve::CurveType::P256, pub, digest, (const uint8_t*)sig.c_str());
    if (!ok) return err_msg_ret(1, "ecdsa: failed to verify the signature.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);

    *out_size = 0;
    return 0;
}

/**
 * @brief Extract mnemonics from sign key.
 *
 * @param[in] in a JSON string
 * {
 *   "sign_key": "a base64 string"
 * }
 * @param[in] in_size length of the input
 * @param[out] out a JSON string
 * {
 *   "mnemo": "mnemonics related to the private key"
 *   "err": (null if successful)
 *   {
 *     "err_code": int
 *     "err_msg": string
 *   }
 * }
 * @param[in/out] out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE extract_mnemo_from_sign_key(const char *in, int in_size, char *out, int *out_size) {
    if (!get_randomness_flag()) {
        return err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    nlohmann::json in_json;
    if (!parse_json_str(in, in_size, in_json, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__ ,out, out_size);
    }

    std::string sign_key_base64;
    if (!json_helper::fetch_json_string_node(in_json, "sign_key", sign_key_base64, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__ ,out, out_size);
    }
    safeheron::multi_party_ecdsa::cmp::SignKey sign_key;
    bool ok = sign_key.FromBase64(sign_key_base64);
    if (!ok) return err_msg_ret(1, "Failed to deserialize sign key.", __FILE__, __FUNCTION__, __LINE__, out, out_size);

    const safeheron::bignum::BN &x = sign_key.local_party_.x_;
    std::string bytes;
    x.ToBytes32BE(bytes);
    std::string mnemo;
    ok = safeheron::bip39::BytesToMnemonic(mnemo, bytes, safeheron::bip39::Language::ENGLISH);
    if (!ok) return err_msg_ret(1, "Failed to covert bytes to mnemonics.", __FILE__, __FUNCTION__, __LINE__, out, out_size);

    std::string verify_bytes;
    ok = safeheron::bip39::MnemonicToBytes(verify_bytes, mnemo, safeheron::bip39::Language::ENGLISH);
    if (!ok) return err_msg_ret(1, "Failed to covert mnemonics to bytes.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    if (bytes != verify_bytes) return err_msg_ret(1, "Secondary verification of bytes-to-mnemonics failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);

    nlohmann::json out_json;
    out_json["mnemo"] = mnemo;

    if (!serialize_json_node(out_json, out, out_size, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

/**
 * @brief Generate a public key with the input mnemonic and it's related discrete logarithm zero knowledge proof.
 *
 * @param[in] in a JSON string
 * {
 *   "curve_type": 1
 *   "mnemo": "mnemonics of the private key"
 * }
 * @param[in] in_size length of the input
 * @param[out] out a JSON string
 * {
 *   "X": "personal signing public key, full encoding in 65 bytes, and encoded as a hex string"
 *   "dlog_zkp": "discrete logarithm zero knowledge proof of it's public key 'X', a base64 string"
 *   "err" (null if successful)
 *   {
 *     "err_code": 1
 *     "err_msg": "xx"
 *   }
 * }
 * @param[in/out] out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE generate_pub_with_zkp(const char *in, int in_size, char *out, int *out_size) {
    if (!get_randomness_flag()) {
        return err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    nlohmann::json in_json;
    if (!parse_json_str(in, in_size, in_json, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__ ,out, out_size);
    }

    int num = in_json["curve_type"];
    if (num != static_cast<int>(safeheron::curve::CurveType::SECP256K1) &&
        num != static_cast<int>(safeheron::curve::CurveType::P256) &&
        num != static_cast<int>(safeheron::curve::CurveType::ED25519)) {
        return err_msg_ret(1, "Invalid curve type.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }
    safeheron::curve::CurveType curve_type = static_cast<safeheron::curve::CurveType>(num);

    std::string mnemo;
    if (!json_helper::fetch_json_string_node(in_json, "mnemo", mnemo, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }
    std::string bytes;
    bool ok = safeheron::bip39::MnemonicToBytes(bytes, mnemo, safeheron::bip39::Language::ENGLISH);
    if (!ok) {
        return err_msg_ret(1, "Failed to covert mnemonics to bytes.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
    safeheron::bignum::BN x;
    try {
        x = safeheron::bignum::BN::FromBytesBE(bytes);
    } catch (std::exception &e) {
        err_msg = e.what();
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::zkp::dlog::DLogProof_V2 dlog_zkp(curve_type);
    dlog_zkp.Prove(x);
    std::string dlog_zkp_b64;
    ok = dlog_zkp.ToBase64(dlog_zkp_b64);
    if (!ok) return err_msg_ret(1, "Failed to serialize the dlog_zkp.", __FILE__, __FUNCTION__, __LINE__, out, out_size);

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(curve_type);
    safeheron::curve::CurvePoint X = curv->g * x;
    uint8_t encoded_pub[65];
    X.EncodeFull(encoded_pub);
    std::string hex = safeheron::encode::hex::EncodeToHex(encoded_pub, 65);

    nlohmann::json out_json;
    out_json["X"] = hex;
    out_json["dlog_zkp"] = dlog_zkp_b64;

    if (!serialize_json_node(out_json, out, out_size, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

/**
 * @brief Generate a minimal sign key with input fields.
 *
 * @param[in] in a JSON string
 * {
 *   "curve_type": 1
 *   "n_parties": 3
 *   "threshold": 2
 *   "party_id": "party_1"
 *   "index": "1"
 *   "mnemo": "mnemonics of the private key"
 *   "X": "personal signing public key, full encoding in 65 bytes, and encoded as a hex string"
 *   "remote_parties":
 *   [
 *     {
 *       "party_id": "party_2"
 *       "index": "2"
 *       "X": "personal signing public key, full encoding in 65 bytes, and encoded as a hex string"
 *       "dlog_zkp": "discrete logarithm zero knowledge proof of it's public key 'X', a base64 string"
 *     },
 *     {
 *       "party_id": "party_3"
 *       "index": "3"
 *       "X": "personal signing public key, full encoding in 65 bytes, and encoded as a hex string"
 *       "dlog_zkp": "discrete logarithm zero knowledge proof of it's public key 'X', a base64 string"
 *     },
 *     ...
 *   ]
 * }
 * @param[in] in_size length of the input
 * @param[out] out a JSON string
 * {
 *   "minimal_sign_key": "a base64 string"
 *   "err": (null if successful)
 *   {
 *     "err_code": 1
 *     "err_msg": "xx"
 *   }
 * }
 * @param[in/out] out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE generate_minimal_key(const char *in, int in_size, char *out, int *out_size) {
    if (!get_randomness_flag()) {
        return err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    MinimalKeyParam minimal_key_param;
    if (!minimal_key_param.FromJson(in, in_size, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::multi_party_ecdsa::cmp::MinimalSignKey minimal_sign_key;
    minimal_sign_key.n_parties_ = minimal_key_param.n_parties_;
    minimal_sign_key.threshold_ = minimal_key_param.threshold_;
    minimal_sign_key.local_party_.party_id_ = minimal_key_param.party_id_;
    minimal_sign_key.local_party_.index_ = minimal_key_param.index_;
    minimal_sign_key.local_party_.x_ = minimal_key_param.x_;
    minimal_sign_key.local_party_.X_ = minimal_key_param.X_;

    std::vector<safeheron::multi_party_ecdsa::cmp::MinimalRemoteParty> &remote_parties = minimal_sign_key.remote_parties_;
    for (size_t i = 0; i < minimal_key_param.remote_party_index_arr_.size(); ++i) {
        remote_parties.emplace_back(safeheron::multi_party_ecdsa::cmp::MinimalRemoteParty());
        remote_parties[i].party_id_ = minimal_key_param.remote_party_id_arr_[i];
        remote_parties[i].index_ = minimal_key_param.remote_party_index_arr_[i];
        remote_parties[i].X_ = minimal_key_param.remote_X_arr_[i];
    }

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(minimal_key_param.curve_type_);

    std::vector<safeheron::bignum::BN> share_index_arr;
    for (size_t i = 0; i < minimal_sign_key.remote_parties_.size(); ++i) {
        share_index_arr.push_back(minimal_sign_key.remote_parties_[i].index_);
    }
    share_index_arr.push_back(minimal_sign_key.local_party_.index_);

    std::vector<safeheron::bignum::BN> l_arr;
    safeheron::sss::Polynomial::GetLArray(l_arr, safeheron::bignum::BN::ZERO, share_index_arr, curv->n);

    safeheron::curve::CurvePoint X = minimal_sign_key.local_party_.X_ * l_arr.back();
    for(size_t i = 0; i < minimal_sign_key.remote_parties_.size(); ++i) {
        X += minimal_sign_key.remote_parties_[i].X_ * l_arr[i];
    }

    minimal_sign_key.X_ = X;

    minimal_sign_key.rid_ = minimal_key_param.gen_rid();

    std::string minimal_sigb_key_base64;
    if (!minimal_sign_key.ValidityTest() || !minimal_sign_key.ToBase64(minimal_sigb_key_base64)) {
        return err_msg_ret(1, "Tests on minimal key failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    nlohmann::json out_json;
    out_json["minimal_sign_key"] = minimal_sigb_key_base64;

    if (!serialize_json_node(out_json, out, out_size, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}
//// ////
/**
 * @brief Generate pedersen parameters used in key generation protocol.
 *
 * @param out a JSON string
 * {
 *   "prepared_data": {
 *     "N", "a hex string"
 *     "s", "a hex string",
 *     "t", "a hex string",
 *     "p", "a hex string",
 *     "q", "a hex string",
 *     "alpha", "a hex string"
 *     "beta", "a hex string"
 *   }
 * }
 * @param out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE prepare_data(char* out, int* out_size) {
    safeheron::multi_party_ecdsa::cmp::PreparedKeyGenData prepared_data;
    safeheron::multi_party_ecdsa::cmp::prepare_data(prepared_data);

    std::string str;
    nlohmann::json out_json;

    nlohmann::json prepared_data_node;
    prepared_data.N_.ToHexStr(str);
    prepared_data_node["N"] = str;
    prepared_data.s_.ToHexStr(str);
    prepared_data_node["s"] = str;
    prepared_data.t_.ToHexStr(str);
    prepared_data_node["t"] = str;
    prepared_data.p_.ToHexStr(str);
    prepared_data_node["p"] = str;
    prepared_data.q_.ToHexStr(str);
    prepared_data_node["q"] = str;
    prepared_data.alpha_.ToHexStr(str);
    prepared_data_node["alpha"] = str;
    prepared_data.beta_.ToHexStr(str);
    prepared_data_node["beta"] = str;

    out_json["prepared_data"] = prepared_data_node;

    std::string err_msg;

    if (!serialize_json_node(out_json, out, out_size, err_msg)) {
        return err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif