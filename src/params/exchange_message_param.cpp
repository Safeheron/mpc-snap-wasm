#include "exchange_message_param.h"
#include "third_party/nlohmann/json.hpp"
#include "../common/tools.h"
#include "../common/json_helper_ex.h"

ExchangeMsgParam::ExchangeMsgParam()
 : context_(0)
 , last_round_index_(0)
 , current_round_index_(0)
 , signature_(nullptr)
 , restored_shard_(nullptr)
{
}

ExchangeMsgParam::~ExchangeMsgParam()
{
    if (signature_) {
        delete signature_;
        signature_ = nullptr;
    }
    if (restored_shard_) {
        delete restored_shard_;
        restored_shard_ = nullptr;
    }
}

bool ExchangeMsgParam::FromJson(const char *str, int size, std::string &err_msg)
{
    nlohmann::json root;
    if (!parse_json_str(str, size, root, err_msg)) return false;

    if (!json_helper::fetch_json_string_node(root, "context", context_, err_msg)) return false;

    if (!json_helper::fetch_json_int_node(root, "last_round_index", last_round_index_, err_msg)) return false;

    message_list_.clear();

    nlohmann::json message_list_node;
    if (!json_helper::fetch_json_object_node(root, "in_message_list", message_list_node, err_msg)) return false;
    for (nlohmann::json::iterator it = message_list_node.begin(); it != message_list_node.end(); ++it) {
        Message message;
        nlohmann::json message_node = *it;

        if (!json_helper::fetch_json_string_node(message_node, "source", message.source_, err_msg)) return false;

        if (!json_helper::fetch_json_string_node(message_node, "destination", message.destination_, err_msg)) return false;

        if (!json_helper::fetch_json_string_node(message_node, "p2p_message", message.p2p_message_, err_msg)) return false;

        if (!json_helper::fetch_json_string_node(message_node, "broadcast_message", message.broadcast_message_, err_msg)) return false;

        message_list_.push_back(message);
    }

    return true;
}

bool ExchangeMsgParam::ToJson(char *out, int *size, std::string &err_msg)
{
    nlohmann::json root;
    root["context"] = context_;
    root["current_round_index"] = current_round_index_;

    if (!message_list_.empty()) {
        nlohmann::json msg_root;
        for (size_t i = 0; i < message_list_.size(); ++i) {
            nlohmann::json msg;
            msg["p2p_message"] = message_list_[i].p2p_message_;
            msg["broadcast_message"] = message_list_[i].broadcast_message_;
            msg["source"] = message_list_[i].source_;
            msg["destination"] = message_list_[i].destination_;
            msg_root.push_back(msg);
        }
        root["out_message_list"] = msg_root;
    }

    if (minimal_sign_key_.length() > 0 && pub_.length() > 0) {
        root["minimal_sign_key"] = minimal_sign_key_;
        root["pub"] = pub_;
    } else if (sign_key_.length() > 0 && pub_.length() > 0) {
        root["sign_key"] = sign_key_;
        root["pub"] = pub_;
    } else if (signature_) {
        nlohmann::json sig;
        sig["r"] = signature_->r_;
        sig["s"] = signature_->s_;
        sig["v"] = signature_->v_;
        root["signature"] = sig;
    } else if (restored_shard_) {
        root["s"] = restored_shard_->s_;
        root["X_k"] = restored_shard_->X_k_;
    } else ;

    if (!serialize_json_node(root, out, size, err_msg)) return false;

    return true;
}
