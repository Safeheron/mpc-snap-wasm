#ifndef SAFEHEON_METAMASK_INTERFACE_COMMON_TOOLS_H
#define SAFEHEON_METAMASK_INTERFACE_COMMON_TOOLS_H

#include <mpc-flow/mpc-parallel-v2/mpc_context.h>
#include "third_party/nlohmann/json.hpp"

std::string get_err_stack_info(const safeheron::mpc_flow::mpc_parallel_v2::MPCContext *ctx);

int err_msg_ret(const int err_code, const std::string &err_info, const std::string &file_name, const std::string &func_name, const int line_num, char *out, int *out_size);

bool parse_json_str(const char *str, int size, nlohmann::json &json, std::string &err_msg);
bool serialize_json_node(const nlohmann::json &json, char *str, int *size, std::string &err_msg);

#endif //SAFEHEON_METAMASK_INTERFACE_COMMON_TOOLS_H
