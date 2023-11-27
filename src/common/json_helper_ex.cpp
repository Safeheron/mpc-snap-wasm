#include "json_helper_ex.h"
#include "crypto-encode/hex.h"
#include <exception>

namespace json_helper {

bool fetch_json_bytes_node(const JSON &root, const std::string &node_name,
                           std::string &value, std::string &err_msg) {
    std::string str_value;
    if (!fetch_json_string_node(root, node_name, str_value, err_msg)) return false;
    value = safeheron::encode::hex::DecodeFromHex(str_value);
    return true;
}

bool fetch_json_bn_node(const JSON &root, const std::string &node_name,
                        safeheron::bignum::BN &value, std::string &err_msg) {
    std::string str_value;
    if (!fetch_json_string_node(root, node_name, str_value, err_msg)) return false;
    value = safeheron::bignum::BN::FromHexStr(str_value);
    return true;
}

bool fetch_json_curve_point_node(const JSON &root, const std::string &node_name, safeheron::curve::CurveType curve_type,
                                 safeheron::curve::CurvePoint &value,
                                 std::string &err_msg) {
    std::string str_value;
    if (!fetch_json_string_node(root, node_name, str_value, err_msg)) return false;
    // 04 + x(32 bytes) + y(32 bytes)
    if (str_value.length() != 130) {
        err_msg = "str_value.length() != 130";
        return false;
    }
    std::string buf65 = safeheron::encode::hex::DecodeFromHex(str_value);
    // check length of byte array
    if (buf65.length() != 65) {
        err_msg = "buf65.length() != 65";
        return false;
    }
    safeheron::curve::CurvePoint t_point(curve_type);
    if (!t_point.DecodeFull((const uint8_t *) buf65.data(), curve_type)) {
        err_msg = "point.DecodeFull(xx)";
        return false;
    }
    value = t_point;
    return true;
}

bool fetch_json_compressed_point_node(const JSON &root, const std::string &node_name, safeheron::curve::CurveType curve_type,
                                      safeheron::curve::CurvePoint &value,
                                      std::string &err_msg) {
    std::string str_value;
    if (!fetch_json_string_node(root, node_name, str_value, err_msg)) return false;

    if (str_value.length() != 66) {
        err_msg = "str_value.length() != 66";
        return false;
    }
    std::string buf33 = safeheron::encode::hex::DecodeFromHex(str_value);
    // check length of byte array
    if (buf33.length() != 33) {
        err_msg = "buf33.length() != 33";
        return false;
    }
    safeheron::curve::CurvePoint t_point(curve_type);
    if (!t_point.DecodeCompressed((const uint8_t *)buf33.data(), curve_type)) {
        err_msg = "point.DecodeCompressed(xx)";
        return false;
    }

    value = t_point;
    return true;
}

bool fetch_json_edwards_point_node(const JSON &root, const std::string &node_name, safeheron::curve::CurveType curve_type,
                                      safeheron::curve::CurvePoint &value,
                                      std::string &err_msg) {
    std::string str_value;
    if (!fetch_json_string_node(root, node_name, str_value, err_msg)) return false;

    if (str_value.length() != 64) {
        err_msg = "str_value.length() != 64";
        return false;
    }
    std::string buf32 = safeheron::encode::hex::DecodeFromHex(str_value);
    // check length of byte array
    if (buf32.length() != 32) {
        err_msg = "buf32.length() != 32";
        return false;
    }
    safeheron::curve::CurvePoint t_point(curve_type);
    if (!t_point.DecodeEdwardsPoint((uint8_t *)buf32.data(), curve_type)) {
        err_msg = "point.DecodeEdwardsPoint(xx)";
        return false;
    }

    value = t_point;
    return true;
}

std::string bn_to_json_str(safeheron::bignum::BN &bn) {
    std::string hex_str;
    bn.ToHexStr(hex_str);
    return hex_str;
}

std::string bytes_to_json_hex(std::string &bytes) {
    return safeheron::encode::hex::EncodeToHex(bytes);
}

std::string point_to_json_str(safeheron::curve::CurvePoint &point) {
    std::string hex_str;
    uint8_t buf[65];
    point.EncodeFull(buf);
    return safeheron::encode::hex::EncodeToHex(buf, 65);
}

std::string compressed_point_to_json_str(safeheron::curve::CurvePoint &point) {
    std::string hex_str;
    uint8_t buf[33];
    point.EncodeCompressed(buf);
    return safeheron::encode::hex::EncodeToHex(buf, 33);
}

std::string edwards_point_to_json_str(safeheron::curve::CurvePoint &point) {
    std::string hex_str;
    uint8_t buf[32];
    point.EncodeEdwardsPoint(buf);
    return safeheron::encode::hex::EncodeToHex(buf, 32);
}

}