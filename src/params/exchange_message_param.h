#ifndef _EXCHANGE_MSG_PARAM_H_
#define _EXCHANGE_MSG_PARAM_H_

#include <string>

class ExchangeMsgParam {
public:
    struct Message {
        std::string p2p_message_;
        std::string broadcast_message_;
        std::string destination_;
        std::string source_;
    };
    struct Signature {
        std::string r_;
        std::string s_;
        int v_;

        Signature():v_(0) {}
        Signature(const std::string &r, const std::string &s, const int v) {
            r_ = r;
            s_ = s;
            v_ = v;
        }
    };
    struct RestoredShard {
        std::string s_;
        std::string X_k_;

        RestoredShard() {}
        RestoredShard(const std::string &s, const std::string &X_k) {
            s_ = s;
            X_k_ = X_k;
        }
    };
public:
    ExchangeMsgParam();
    ~ExchangeMsgParam();
public:
    bool FromJson(const char *str, int size, std::string &err_msg); //for in message
    bool ToJson(char *out, int *size, std::string &err_msg); //for out message

public:
    long context_;
    int last_round_index_; //for in msg
    int current_round_index_;  //for out msg
    std::vector<Message> message_list_;

    std::string minimal_sign_key_;
    std::string sign_key_;
    std::string pub_;

    Signature* signature_;
    RestoredShard* restored_shard_;
};

#endif //_EXCHANGE_MSG_PARAM_H_