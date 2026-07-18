#include "posix_internal.h"

// SignalQueue 实现（声明见 posix_syscall.h）。
// 容量上限沿用 BPF_SIGNAL_QUE_SIZE：信号风暴下满则丢弃，防止 deque 无限增长 OOM。

bool SignalQueue::push(SigEvent v) {
    std::lock_guard<std::mutex> lk(mtx_);
    if(q_.size() >= BPF_SIGNAL_QUE_SIZE) {
        return false;   // 满则丢弃，与原 MpscQueue try_push 失败语义一致
    }
    q_.push_back(v);
    return true;
}

bool SignalQueue::pop(SigEvent& v) {
    std::lock_guard<std::mutex> lk(mtx_);
    if(q_.empty()) return false;
    v = q_.front();
    q_.pop_front();
    return true;
}

bool SignalQueue::empty() {
    std::lock_guard<std::mutex> lk(mtx_);
    return q_.empty();
}
