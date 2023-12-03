#include <emscripten.h>
#include <vector>

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

#include <multi-party-ecdsa/cmp/minimal_sign_key.h>
#include <multi-party-ecdsa/cmp/sign_key.h>
#include <multi-party-ecdsa/cmp/util.h>

#include "nlohmann/json.hpp"
#include "params/minimal_key_param.h"
#include "common/tools.h"
#include "common/json_helper_ex.h"
#include "common/global_variables.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Set random seed for openssl.
 *
 * @param[in] seed : Bytes of a random seed.
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
    safeheron::mpc_snap_wasm::common::set_randomness_flag();
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
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
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
 *   "priv": "06C34C90CF4503C5B607285EDB9E32097519DC94FB2A2A03D5C502628C0318FB"
 *   "pub": "0445a5fa34f82ea8cc2e421127b00fcb975528bb34db4cad0109cb792cd68d263835c484a861e6f75a696ad3ba4fe97e7ef68bbaa560279c906a87c375ef43db68"
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
int EMSCRIPTEN_KEEPALIVE generate_key_pair(int curve_type, char *out, int *out_size) {
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }

    if (curve_type != static_cast<int>(safeheron::curve::CurveType::SECP256K1) &&
        curve_type != static_cast<int>(safeheron::curve::CurveType::P256) &&
        curve_type != static_cast<int>(safeheron::curve::CurveType::ED25519)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Invalid curve type.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
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
    if (!safeheron::mpc_snap_wasm::common::serialize_json_node(out_json, out, out_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

/**
 * @brief Encryption with ECIES algorithm
 *
 * @param[in] in a JSON string
 * {
 *   "local_priv": "1042D9ABF74D07A1B97F18D88632584EB40CB3DECA32F416EE5EBFBC8DE14E19"
 *   "remote_pub": "048041c19fd4ff73e057f481607e8210ac56fc1f311f878d87906bd8b852b754698298b3a382e847b2d4dd5ef858f85691aba3124726b234b4702269584c2b4366"
 *   "plain": "000102030405"
 * }
 * @param[in] in_size length of the input
 * @param[out] out a JSON string
 * {
 *   "cypher": "04c9d3399df6ae7d77d1f786dd...8e034cb837211d1dc0b7c5747b772708cae915b486e59"
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
int EMSCRIPTEN_KEEPALIVE AuthEnc_encrypt(const char *in, int in_size, char *out, int *out_size) {
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    nlohmann::json in_json;
    if (!safeheron::mpc_snap_wasm::common::parse_json_str(in, in_size, in_json, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::bignum::BN local_priv;
    if (!json_helper::fetch_json_bn_node(in_json, "local_priv", local_priv, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::curve::CurvePoint remote_pub;
    if (!json_helper::fetch_json_curve_point_node(in_json, "remote_pub", safeheron::curve::CurveType::P256, remote_pub, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string plain;
    if (!json_helper::fetch_json_string_node(in_json, "plain", plain, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::ecies::AuthEnc enc;
    std::string cypher;
    bool ok = enc.Encrypt(local_priv, remote_pub, plain, cypher);
    if (!ok) return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "AuthEnc: encryption failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);

    nlohmann::json out_json;
    out_json["cypher"] = safeheron::encode::hex::EncodeToHex(cypher);

    if (!safeheron::mpc_snap_wasm::common::serialize_json_node(out_json, out, out_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

/**
 * @brief ECIES Decryption
 *
 * @param[in] in a JSON string
 * {
 *   "local_priv": "953190D490B4CC9E0411A837A4F89DE163E7B3815B3858FB25C77EE8BC2846C1"
 *   "remote_pub": "0436648e9e6a1ad6abc150c856682edac1359404a5046897d091ec13710d90fd4a045f643b2993ce70a6a53e0afc5760d7f3a4d2ca54376c8fd1d148e8dc671553"
 *   "cypher": "04c9d3399df6ae7d77d1f786dd...8e034cb837211d1dc0b7c5747b772708cae915b486e59"
 * }
 * @param[in] in_size length of the input
 * @param[out] out a JSON string
 * {
 *   "plain": "000102030405"
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
int EMSCRIPTEN_KEEPALIVE AuthEnc_decrypt(const char *in, int in_size, char *out, int *out_size) {
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    nlohmann::json in_json;
    if (!safeheron::mpc_snap_wasm::common::parse_json_str(in, in_size, in_json, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::bignum::BN local_priv;
    if (!json_helper::fetch_json_bn_node(in_json, "local_priv", local_priv, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::curve::CurvePoint remote_pub;
    if (!json_helper::fetch_json_curve_point_node(in_json, "remote_pub", safeheron::curve::CurveType::P256, remote_pub, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string cypher;
    if (!json_helper::fetch_json_bytes_node(in_json, "cypher", cypher, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::ecies::AuthEnc enc;
    std::string plain;
    bool ok = enc.Decrypt(local_priv, remote_pub, cypher, plain);
    if (!ok) return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "AuthEnc: decryption failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);

    nlohmann::json out_json;
    out_json["plain"] = plain;

    if (!safeheron::mpc_snap_wasm::common::serialize_json_node(out_json, out, out_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

/**
 * @brief ECDSA signature algorithm.
 *
 * @param[in] in a JSON string
 * {
 *   "priv": "06C34C90CF4503C5B607285EDB9E32097519DC94FB2A2A03D5C502628C0318FB"
 *   "digest": "2915115276233FAA1EC551B2A31201D483925E00053CD557C3D0504C74D5C952" //digest to be signed, encoded as a hex string
 * }
 * @param[in] in_size length of the input
 * @param[out] out a JSON string
 * {
 *   "sig": "2CC39DC7CA357E6D5FD218A4D8D87AB70E42EACAB2064CA0F0E95B0CC7EAA169D74355A86449F95A29C31032CAAE66BF28D5981B55F8E28B5006C92AEFCBF664"
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
int EMSCRIPTEN_KEEPALIVE ecdsa_sign(const char *in, int in_size, char *out, int *out_size) {
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    const size_t DIGEST_SIZE = 32;
    const size_t SIG_SIZE = 64;

    nlohmann::json in_json;
    if (!safeheron::mpc_snap_wasm::common::parse_json_str(in, in_size, in_json, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::bignum::BN priv;
    if (!json_helper::fetch_json_bn_node(in_json, "priv", priv, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string digest_bytes;
    if (!json_helper::fetch_json_bytes_node(in_json, "digest", digest_bytes, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
    if (digest_bytes.length() != DIGEST_SIZE) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Invalid digest length.",  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
    uint8_t digest[DIGEST_SIZE] = {0};
    memcpy(digest, digest_bytes.c_str(), digest_bytes.length());

    uint8_t sig[SIG_SIZE];
    safeheron::curve::ecdsa::Sign(safeheron::curve::CurveType::P256, priv, digest, sig);

    nlohmann::json out_json;
    out_json["sig"] = safeheron::encode::hex::EncodeToHex(sig, SIG_SIZE);;

    if (!safeheron::mpc_snap_wasm::common::serialize_json_node(out_json, out, out_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

/**
 * @brief ECDSA signature verification algorithm.
 *
 * @param[in] in a JSON string
 * {
 *   "pub": "0445a5fa34f82ea8cc2e421127b00fcb975528bb34db4cad0109cb792cd68d263835c484a861e6f75a696ad3ba4fe97e7ef68bbaa560279c906a87c375ef43db68"
 *   "digest": "2915115276233FAA1EC551B2A31201D483925E00053CD557C3D0504C74D5C952"
 *   "sig": "2CC39DC7CA357E6D5FD218A4D8D87AB70E42EACAB2064CA0F0E95B0CC7EAA169D74355A86449F95A29C31032CAAE66BF28D5981B55F8E28B5006C92AEFCBF664"
 * }
 * @param[in] in_size length of the input
 * @param[out] out Null if successful
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
int EMSCRIPTEN_KEEPALIVE ecdsa_verify(const char *in, int in_size, char *out, int *out_size) {
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    const size_t DIGEST_SIZE = 32;
    const size_t SIG_SIZE = 64;

    nlohmann::json in_json;
    if (!safeheron::mpc_snap_wasm::common::parse_json_str(in, in_size, in_json, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::curve::CurvePoint pub;
    if (!json_helper::fetch_json_curve_point_node(in_json, "pub", safeheron::curve::CurveType::P256, pub, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string digest_bytes;
    if (!json_helper::fetch_json_bytes_node(in_json, "digest", digest_bytes, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
    if (digest_bytes.length() != DIGEST_SIZE) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Invalid digest length.",  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
    uint8_t digest[DIGEST_SIZE] = {0};
    memcpy(digest, digest_bytes.c_str(), digest_bytes.length());

    std::string sig;
    if (!json_helper::fetch_json_bytes_node(in_json, "sig", sig, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg,  __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }
    if (sig.length() != SIG_SIZE) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "The length of the signature is not proper.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }

    bool ok = safeheron::curve::ecdsa::Verify(safeheron::curve::CurveType::P256, pub, digest, (const uint8_t*)sig.c_str());
    if (!ok) return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Failed to verify the signature.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);

    *out_size = 0;
    return 0;
}

/**
 * @brief Extract mnemonics from sign key.
 *
 * @param[in] in a JSON string
 * {
 *   "sign_key": "EAIYAyKEGwoKY29fc2l...ViYWVhY2JmZTEwYmU4MDkyN2RhMzAyYmZjMzVkOTlkOWU4ZmJhNTY5ZGZiMDNmZDFlMzY3MTMyZjNkZg.."
 * }
 * @param[in] in_size length of the input
 * @param[out] out a JSON string
 * {
 *   "mnemo": "animal exhaust still crack mosquito resist cart scorpion actress veteran toss digital buzz photo dress scissors rough card wear unhappy bind perfect mountain worth"
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
int EMSCRIPTEN_KEEPALIVE extract_mnemo_from_sign_key(const char *in, int in_size, char *out, int *out_size) {
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    nlohmann::json in_json;
    if (!safeheron::mpc_snap_wasm::common::parse_json_str(in, in_size, in_json, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__ ,out, out_size);
    }

    std::string sign_key_base64;
    if (!json_helper::fetch_json_string_node(in_json, "sign_key", sign_key_base64, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__ ,out, out_size);
    }
    safeheron::multi_party_ecdsa::cmp::SignKey sign_key;
    bool ok = sign_key.FromBase64(sign_key_base64);
    if (!ok) return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Failed to deserialize sign key.", __FILE__, __FUNCTION__, __LINE__, out, out_size);

    const safeheron::bignum::BN &x = sign_key.local_party_.x_;
    std::string bytes;
    x.ToBytes32BE(bytes);
    std::string mnemo;
    ok = safeheron::bip39::BytesToMnemonic(mnemo, bytes, safeheron::bip39::Language::ENGLISH);
    if (!ok) return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Failed to covert bytes to mnemonics.", __FILE__, __FUNCTION__, __LINE__, out, out_size);

    std::string verify_bytes;
    ok = safeheron::bip39::MnemonicToBytes(verify_bytes, mnemo, safeheron::bip39::Language::ENGLISH);
    if (!ok) return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Failed to covert mnemonics to bytes.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    if (!(safeheron::multi_party_ecdsa::cmp::compare_bytes(bytes, verify_bytes) == 0)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Secondary verification of bytes to mnemonics failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    nlohmann::json out_json;
    out_json["mnemo"] = mnemo;

    if (!safeheron::mpc_snap_wasm::common::serialize_json_node(out_json, out, out_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

/**
 * curve_type : specific elliptic curve
 * - 1 represents Secp256k1
 * - 2 represents P256
 * - 2^5 represents ED25519
 */
/**
 * @brief Generate a public key with the input mnemonic and it's related discrete logarithm zero knowledge proof.
 *
 * @param[in] in a JSON string
 * {
 *   "curve_type": 1
 *   "mnemo": "speak luxury history camera raccoon cargo setup real night milk advice mandate broken age resource dilemma indoor jar meadow timber valid render boss wool"
 * }
 * @param[in] in_size length of the input
 * @param[out] out a JSON string
 * {
 *   "X": "042d79c4b78f4b6fb1f91ed9b44ae7b2637b8434e3f80942f290d140b1998ca90b532fe12c193a92beac565ed5992f0e2a3406e2385da39669ce607b920a2f3da0"
 *   "dlog_zkp": "Eo8BCkAwRjU3MjQz...1NjY1MzkxMUQ1MzcwNkYzNDg"
 * }
 * If errors occur, output:
 * {
 *   "err":
 *   {
 *     "err_code": int
 *     "err_msg": string
 *   }
 * }
 * @param[in/out] out_size in: maximum capacity of the output buffer, out: length of the output
 * @return Return 0 if successful, otherwise, return an error code.
 */
int EMSCRIPTEN_KEEPALIVE generate_pub_with_zkp(const char *in, int in_size, char *out, int *out_size) {
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    nlohmann::json in_json;
    if (!safeheron::mpc_snap_wasm::common::parse_json_str(in, in_size, in_json, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__ ,out, out_size);
    }

    int num;
    if (!json_helper::fetch_json_int_node(in_json, "curve_type", num, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }
    if (num != static_cast<int>(safeheron::curve::CurveType::SECP256K1) &&
        num != static_cast<int>(safeheron::curve::CurveType::P256) &&
        num != static_cast<int>(safeheron::curve::CurveType::ED25519)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Invalid curve type.", __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }
    safeheron::curve::CurveType curve_type = static_cast<safeheron::curve::CurveType>(num);

    std::string mnemo;
    if (!json_helper::fetch_json_string_node(in_json, "mnemo", mnemo, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__ , __LINE__, out, out_size);
    }
    std::string bytes;
    bool ok = safeheron::bip39::MnemonicToBytes(bytes, mnemo, safeheron::bip39::Language::ENGLISH);
    if (!ok) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Failed to covert mnemonics to bytes.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string verify_mneno;
    ok = safeheron::bip39::BytesToMnemonic(verify_mneno, bytes, safeheron::bip39::Language::ENGLISH);
    if (!ok) return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Failed to covert bytes to mnemonicd.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    if (mnemo != verify_mneno) return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Secondary verification of mnemonics to bytes failed.", __FILE__, __FUNCTION__, __LINE__, out, out_size);

    safeheron::bignum::BN x;
    try {
        x = safeheron::bignum::BN::FromBytesBE(bytes);
    } catch (std::exception &e) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, e.what(), __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    safeheron::zkp::dlog::DLogProof_V2 dlog_zkp(curve_type);
    dlog_zkp.Prove(x);
    std::string dlog_zkp_base64;
    ok = dlog_zkp.ToBase64(dlog_zkp_base64);
    if (!ok) return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Failed to serialize dlog_zkp.", __FILE__, __FUNCTION__, __LINE__, out, out_size);

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(curve_type);
    safeheron::curve::CurvePoint X = curv->g * x;
    uint8_t encoded_pub[65];
    X.EncodeFull(encoded_pub);

    nlohmann::json out_json;
    out_json["X"] = safeheron::encode::hex::EncodeToHex(encoded_pub, 65);;
    out_json["dlog_zkp"] = dlog_zkp_base64;

    if (!safeheron::mpc_snap_wasm::common::serialize_json_node(out_json, out, out_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
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
 *   "mnemo": "animal exhaust still crack mosquito resist cart scorpion actress veteran toss digital buzz photo dress scissors rough card wear unhappy bind perfect mountain worth"
 *   "X": ""04fe842b69c4491ff08ebbf96564537ae7dfd20a709216f99a75d096f90567a4a2562fec557c8658bd4ea13f6503bcc214269f79c685145baf75994ec486756085
 *   "remote_parties":
 *   [
 *     {
 *       "party_id": "party_2"
 *       "index": "2"
 *       "X": "0497dc9c46d96e974a34b9071750779eddb2898bf7404e189ee5901f63fa2456ae6dd179c19a1b4f99171517ccb65dabe3732dc646512fcb4558b35742cf86a556"
 *       "dlog_zkp": "Eo8BCkBENTIy...0JFRjdGNjVCMkE5QUNEOTkxMkU1QzBGMzdEOTk"
 *     },
 *     {
 *       "party_id": "party_3"
 *       "index": "3"
 *       "X": "047baf546b507a58658d141c9bff71dfeca8e7326d500bab3c63f26561e5b83f2f7bda5177e6a86516fd1958e7a0e5983bf6f09529c084f2e4fbfcf8304a16bfd8"
 *       "dlog_zkp": "Eo8BCkAzNjc0...NjY1MTFGMDM3QkM4REZCMjY4RjFEQkE0NzZCNjJEQ0Q"
 *     },
 *     ...
 *   ]
 * }
 * @param[in] in_size length of the input
 * @param[out] out a JSON string
 * {
 *   "minimal_sign_key": "EAIYAyLeAQoKY29fc2lnbmVy...JjMDdiNzRiYjg1YTcxYzY4ZTQ2MjBkZWY4"
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
int EMSCRIPTEN_KEEPALIVE generate_minimal_key(const char *in, int in_size, char *out, int *out_size) {
    if (!safeheron::mpc_snap_wasm::common::get_randomness_flag()) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Random seed is not set.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    std::string err_msg;

    safeheron::mpc_snap_wasm::params::MinimalKeyParam minimal_key_param;
    if (!minimal_key_param.FromJson(in, in_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
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

    std::string minimal_sign_key_base64;
    if (!minimal_sign_key.ValidityTest() || !minimal_sign_key.ToBase64(minimal_sign_key_base64)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, "Failed to verify minimal sign key.", __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    nlohmann::json out_json;
    out_json["minimal_sign_key"] = minimal_sign_key_base64;

    if (!safeheron::mpc_snap_wasm::common::serialize_json_node(out_json, out, out_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

/**
 * @brief Generate pedersen parameters used in key generation protocol.
 *
 * @param out a JSON string
 * {
 *   "prepared_data": {
 *     "N": "C269479355E6019...AA29C903A8C53736988381D7153A874F109B309E0171"
 *     "s": "7FA835F34D666D6...7191EA5C8BD6493C9B6DA4A2BBE45CBBB910A110FECF"
 *     "t": "29557C1EC62D4EA...BD4EBFD63AE7AF94EED00313766F5DA016A3A0CA7EF8"
 *     "p": "6B024DF6B38A...1D62BA86E98227"
 *     "q": "7446096AD00E...CB0361538A5371F"
 *     "alpha": "2B9DFE0EAB6BA...3D3F8152F98E2AF761E9BDEEF7FA294398236495E8"
 *     "beta": "077AA740AD281A...2820F437D317DD00D3628B42BFA8135B47AFA7734F"
 *   }
 * }
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
int EMSCRIPTEN_KEEPALIVE prepare_data(char* out, int* out_size) {
    safeheron::bignum::BN N;
    safeheron::bignum::BN s;
    safeheron::bignum::BN t;
    safeheron::bignum::BN p;
    safeheron::bignum::BN q;
    safeheron::bignum::BN alpha;
    safeheron::bignum::BN beta;
    safeheron::multi_party_ecdsa::cmp::prepare_data(N, s, t, p, q, alpha, beta);

    std::string str;
    nlohmann::json out_json;

    nlohmann::json prepared_data_node;
    N.ToHexStr(str);
    prepared_data_node["N"] = str;
    s.ToHexStr(str);
    prepared_data_node["s"] = str;
    t.ToHexStr(str);
    prepared_data_node["t"] = str;
    p.ToHexStr(str);
    prepared_data_node["p"] = str;
    q.ToHexStr(str);
    prepared_data_node["q"] = str;
    alpha.ToHexStr(str);
    prepared_data_node["alpha"] = str;
    beta.ToHexStr(str);
    prepared_data_node["beta"] = str;

    out_json["prepared_data"] = prepared_data_node;

    std::string err_msg;

    if (!safeheron::mpc_snap_wasm::common::serialize_json_node(out_json, out, out_size, err_msg)) {
        return safeheron::mpc_snap_wasm::common::err_msg_ret(1, err_msg, __FILE__, __FUNCTION__, __LINE__, out, out_size);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif