#pragma once

#include <atomic>
#include <queue>
#include <mutex>
#include <stdexcept>
#include <condition_variable>
#include <optional>

template<typename T>
class SafeQueue {
public:
    void push(T value) {
        {
            std::lock_guard lock(this->mutex);
            this->queue.push(value);
            this->closed = false;
        }
        this->cv.notify_one();
    }

    bool is_empty() {
        std::lock_guard lock(this->mutex);
        return this->queue.empty();
    }

    std::optional<T> pop() {
        std::unique_lock lock(this->mutex);

        this->cv.wait(lock, [&](){
            return !this->queue.empty() || this->closed;
        });

        if (this->queue.empty() && this->closed) {
            return std::nullopt;
        }
        auto value = queue.front();
        this->queue.pop();
        return value;
    }

    size_t size() {
        std::lock_guard lock(this->mutex);
        return this->queue.size();
    }

private:
    std::queue<T> queue;
    std::mutex mutex;
    std::condition_variable cv;
    std::atomic<bool> closed = false;
};
