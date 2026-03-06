#include "syscall_handler.h"
#include "insn.h"

bool empty_syscall(vm& v, uint32_t call) {
    (void)call;
    v.r(0) = -ENOSYS;
    return true;
}
