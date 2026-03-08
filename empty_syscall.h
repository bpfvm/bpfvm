#ifndef EMPTY_SYSCALL_H__
#define EMPTY_SYSCALL_H__
#include "insn.h"


class EmptySyscall: public SyscallHandler{
public:
    virtual void init(const std::shared_ptr<vm>&) override{}
    virtual void fini(const std::shared_ptr<vm>&) override{}
    virtual bool syscall(vm* v, uint32_t call) override{
        (void)call;
        v->r(0) = -ENOSYS;
        return true;
    }
    virtual int id() override {
        return 1;
    }
    virtual void queue_signal(vm* v, int sig) override {
        (void)v;
        (void)sig;
    }
    virtual bool handle_signals(vm* v) override {
        (void)v;
        return true;
    }
};

#endif