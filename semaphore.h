#pragma once
#include <mutex>
#include <string>


class Semaphore 
{
public:
    Semaphore(int count = 0) : count_(count)
    {
    }
    void notify() 
    {
        std::unique_lock<std::mutex> lock(mutex_);
        ++count_;
        cv_.notify_one();
    }

    void wait() 
    {
        std::unique_lock<std::mutex> lock(mutex_);
        while (count_ == 0) 
        {
            cv_.wait(lock);
        }
        --count_;
    }
    int available() const 
    {
        return count_;
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    int count_;
};