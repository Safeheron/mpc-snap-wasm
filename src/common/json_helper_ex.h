#ifndef SAFEHERON_MPC_SNAP_WASM_COMMON_JSON_HELPER_EX_H
#define SAFEHERON_MPC_SNAP_WASM_COMMON_JSON_HELPER_EX_H

#include <string>
#include "json_helper.h"
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"

namespace json_helper {

// hex string  => bytes
bool fetch_json_bytes_node(const JSON &root, const std::string &node_name,
                           std::string &value, std::string &err_msg);

bool fetch_json_bn_node(const JSON &root, const std::string &node_name,
                        safeheron::bignum::BN &value, std::string &err_msg);

bool fetch_json_curve_point_node(const JSON &root, const std::string &node_name, safeheron::curve::CurveType curve_type,
                                 safeheron::curve::CurvePoint &value,
                                 std::string &err_msg);

bool fetch_json_compressed_point_node(const JSON &root, const std::string &node_name, safeheron::curve::CurveType curve_type,
                                 safeheron::curve::CurvePoint &value,
                                 std::string &err_msg);

bool fetch_json_edwards_point_node(const JSON &root, const std::string &node_name, safeheron::curve::CurveType curve_type,
                                      safeheron::curve::CurvePoint &value,
                                      std::string &err_msg);

std::string bn_to_json_str(safeheron::bignum::BN &bn);

std::string bytes_to_json_hex(std::string &bn);

std::string point_to_json_str(safeheron::curve::CurvePoint &point);

std::string compressed_point_to_json_str(safeheron::curve::CurvePoint &point);

std::string edwards_point_to_json_str(safeheron::curve::CurvePoint &point);
}

#endif //SAFEHERON_MPC_SNAP_WASM_COMMON_JSON_HELPER_EX_H