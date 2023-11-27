#ifndef THREAD_SAFE_POINTER_CONTAINER_H
#define THREAD_SAFE_POINTER_CONTAINER_H
#include <thread>
#include <mutex>
#include <vector>
#include "exception/located_exception.h"

template<typename T>
class ThreadSafePointerContainer {
private:
    std::vector<T*> shared_vector_;
    //non-copyable
    std::mutex mut_;

private:
    T* InternalFind(long ptr) {
        for (size_t i = 0; i < shared_vector_.size(); ++i) {
            if ((long)shared_vector_[i] == ptr) {
                return shared_vector_[i];
            }
        }
        return nullptr;
    }
public:
    long Push(T* ptr) {
        if (ptr == nullptr) throw safeheron::exception::LocatedException(__FILE__, __LINE__, __FUNCTION__, 1, "Null pointer!");

        std::lock_guard<std::mutex> lk(mut_);
        if (!InternalFind((long)ptr)) shared_vector_.push_back(ptr);
        return (long)ptr;
    }

    void Remove(long ptr) {
        std::lock_guard<std::mutex> lk(mut_);
        for (auto it = shared_vector_.begin(); it != shared_vector_.end(); ++it) {
            if ((long)(*it) == ptr) {
                delete *it;
                shared_vector_.erase(it);
                return;
            }
        }
    }

    void Clear() {
        std::lock_guard<std::mutex> lk(mut_);
        for (size_t i = 0; i < shared_vector_.size(); ++i) {
            delete shared_vector_[i];
        }
        shared_vector_.clear();
    }

    T* Find(long ptr) {
        std::lock_guard<std::mutex> lk(mut_);
        return InternalFind(ptr);
    }
};

#endif //THREAD_SAFE_POINTER_CONTAINER_H
