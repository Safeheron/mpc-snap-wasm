#ifndef SAFEHERON_MPC_SNAP_WASM_COMMON_THREAD_SAFE_POINTER_CONTAINER_H
#define SAFEHERON_MPC_SNAP_WASM_COMMON_THREAD_SAFE_POINTER_CONTAINER_H
#include <thread>
#include <mutex>
#include <cstdint>
#include <vector>
#include "exception/located_exception.h"
namespace safeheron {
namespace mpc_snap_wasm {
namespace common {
template<typename T>
class ThreadSafePointerContainer {
private:
    std::vector<T *> shared_vector_;
    //non-copyable
    std::mutex mut_;
private:
    T *InternalFind(const std::string &ptr_str) {
        for (size_t i = 0; i < shared_vector_.size(); ++i) {
            if (std::to_string(reinterpret_cast<std::uintptr_t>(shared_vector_[i])) == ptr_str) {
                return shared_vector_[i];
            }
        }
        return nullptr;
    }

public:
    ThreadSafePointerContainer() = default;

    std::string Push(T *ptr) {
        if (ptr == nullptr)
            throw safeheron::exception::LocatedException(__FILE__, __LINE__, __FUNCTION__, 1,
                                                         "Null pointer!");

        std::lock_guard<std::mutex> lk(mut_);
        std::string ptr_str = std::to_string(reinterpret_cast<std::uintptr_t>(ptr));
        if (!InternalFind(ptr_str)) shared_vector_.push_back(ptr);
        return ptr_str;
    }

    void Remove(const std::string &ptr_str) {
        std::lock_guard<std::mutex> lk(mut_);
        for (auto it = shared_vector_.begin(); it != shared_vector_.end(); ++it) {
            if (std::to_string(reinterpret_cast<std::uintptr_t>(*it)) == ptr_str) {
                shared_vector_.erase(it);
                break;
            }
        }
    }

    T *Find(const std::string &ptr_str) {
        std::lock_guard<std::mutex> lk(mut_);
        return InternalFind(ptr_str);
    }
};
}
}
}
#endif //SAFEHERON_MPC_SNAP_WASM_COMMON_THREAD_SAFE_POINTER_CONTAINER_H
