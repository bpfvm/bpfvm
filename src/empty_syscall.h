#ifndef EMPTY_SYSCALL_H__
#define EMPTY_SYSCALL_H__
#include "insn.h"


class EmptySyscall: public SyscallHandler{
public:
    virtual void init(const std::shared_ptr<vm>&) override{}
    virtual void fini(const std::shared_ptr<vm>&) override{}
    virtual int64_t syscall(vm*, uint32_t) override{
        return -ENOSYS;
    }
    virtual int id() override {
        return 1;
    }
    virtual bool handle_signals(vm* v) override {
        (void)v;
        return true;
    }
};

#endif