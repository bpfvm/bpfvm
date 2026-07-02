#include "posix_internal.h"

MpscQueue::MpscQueue() {
    for(size_t i = 0; i < k_capacity; ++i) {
        slots[i].seq.store(i, std::memory_order_relaxed);
    }
}

bool MpscQueue::try_push(int value) {
    uint64_t pos = tail.load(std::memory_order_relaxed);
    while(true) {
        slot& s = slots[pos & k_mask];
        uint64_t seq = s.seq.load(std::memory_order_acquire);
        intptr_t dif = (intptr_t)seq - (intptr_t)pos;
        if(dif == 0) {
            if(tail.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                s.value = value;
                s.seq.store(pos + 1, std::memory_order_release);
                return true;
            }
        } else if(dif < 0) {
            return false;
        } else {
            pos = tail.load(std::memory_order_relaxed);
        }
    }
}

bool MpscQueue::try_pop(int& value) {
    uint64_t pos = head.load(std::memory_order_relaxed);
    while(true) {
        slot& s = slots[pos & k_mask];
        uint64_t seq = s.seq.load(std::memory_order_acquire);
        intptr_t dif = (intptr_t)seq - (intptr_t)(pos + 1);
        if(dif == 0) {
            if(head.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                value = s.value;
                s.seq.store(pos + k_capacity, std::memory_order_release);
                return true;
            }
        } else if(dif < 0) {
            return false;
        } else {
            pos = head.load(std::memory_order_relaxed);
        }
    }
}
