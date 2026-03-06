#ifndef SYSCALL_HANDLER_H
#define SYSCALL_HANDLER_H

#include <stdint.h>

class vm;
using syscall_handler_t = bool(*)(vm&, uint32_t);

bool posix_syscall(vm& v, uint32_t call);
bool empty_syscall(vm& v, uint32_t call);

#endif //SYSCALL_HANDLER_H
