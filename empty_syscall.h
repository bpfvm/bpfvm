#ifndef EMPTY_SYSCALL_H__
#define EMPTY_SYSCALL_H__
#include "insn.h"


class EmptySyscall: public SyscallHandler{
    std::weak_ptr<vm> v;
public:
    virtual void init(const std::shared_ptr<vm>& v_) override{
        v = v_;
    }
    virtual bool dispatch(uint32_t call) override{
        (void)call;
        auto locked = v.lock();
        if(locked) {
            locked->r(0) = -ENOSYS;
            return true;
        }
        return false;
    }
    virtual int id() override {
        return 1;
    }
};

#endif