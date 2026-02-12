//
// Created by chouryzhou on 24-10-28.
//

#ifndef INSN_H
#define INSN_H
#include <list>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <atomic>
#include <array>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <string>
#include <unordered_map>
#include <vector>

#include "include/bpf_call.h"
namespace bpf{
    #define BPF_NO_SYSCALL
    #include "include/signal.h"
    #include "include/sys/stat.h"
    #include "include/dirent.h"
    #include "include/sys/times.h"
    #include "include/termios.h"
}

#define STACK_SIZE (8 * 1024 * 1024)
#define STACK_BASE 0x10000000ULL
#define STACK_LIMIT 4096

#ifndef PF_X
#define PF_X		0x1
#endif
#ifndef PF_W
#define PF_W		0x2
#endif
#ifndef PF_R
#define PF_R		0x4
#endif

struct bpf_insn {
    uint8_t	code;		/* opcode */
    uint8_t	dst_reg:4;	/* dest register */
    uint8_t	src_reg:4;	/* source register */
    int16_t	off;		/* signed offset */
    int32_t	imm;		/* signed immediate constant */
};

/*
For arithmetic and jump instructions the 8-bit 'code'
field is divided into three parts:
  +----------------+--------+--------------------+
  |   4 bits       |  1 bit |   3 bits           |
  | operation code | source | instruction class  |
  +----------------+--------+--------------------+
  (MSB)                                      (LSB)
 */

// classes
#define BPF_LD    0x00
#define BPF_LDX   0x01
#define BPF_ST    0x02
#define BPF_STX   0x03
#define BPF_ALU   0x04
#define BPF_JMP   0x05
#define BPF_JMP32 0x06
#define BPF_ALU64 0x07

// source operands
#define BPF_K     0x00 //use 32-bit immediate as source operand
#define BPF_X     0x08 //use 'src_reg' register as source operand

// op for BPF_ALU and BPF_ALU64
#define BPF_ADD   0x00
#define BPF_SUB   0x10
#define BPF_MUL   0x20
#define BPF_DIV   0x30
#define BPF_OR    0x40
#define BPF_AND   0x50
#define BPF_LSH   0x60
#define BPF_RSH   0x70
#define BPF_NEG   0x80
#define BPF_MOD   0x90
#define BPF_XOR   0xa0
#define BPF_MOV   0xb0  /* eBPF only: mov reg to reg */
#define BPF_ARSH  0xc0  /* eBPF only: sign extending shift right */
#define BPF_END   0xd0  /* eBPF only: endianness conversion */

//op for BPF_JMP and BPF_JMP32
#define BPF_JA    0x00  /* BPF_JMP only */
#define BPF_JEQ   0x10
#define BPF_JGT   0x20
#define BPF_JGE   0x30
#define BPF_JSET  0x40
#define BPF_JNE   0x50  /* eBPF only: jump != */
#define BPF_JSGT  0x60  /* eBPF only: signed '>' */
#define BPF_JSGE  0x70  /* eBPF only: signed '>=' */
#define BPF_CALL  0x80  /* eBPF BPF_JMP only: function call */
#define BPF_EXIT  0x90  /* eBPF BPF_JMP only: function return */
#define BPF_JLT   0xa0  /* eBPF only: unsigned '<' */
#define BPF_JLE   0xb0  /* eBPF only: unsigned '<=' */
#define BPF_JSLT  0xc0  /* eBPF only: signed '<' */
#define BPF_JSLE  0xd0  /* eBPF only: signed '<=' */

/*
For load and store instructions the 8-bit 'code' field is divided as:
  +--------+--------+-------------------+
  | 3 bits | 2 bits |   3 bits          |
  |  mode  |  size  | instruction class |
  +--------+--------+-------------------+
  (MSB)                             (LSB)
*/
// Size modifier for load and store
#define BPF_W   0x00    /* word */
#define BPF_H   0x08    /* half word */
#define BPF_B   0x10    /* byte */
#define BPF_DW  0x18    /* eBPF only, double word */

// Mode modifier for load and store
#define BPF_IMM  0x00  /* used for 32-bit mov in classic BPF and 64-bit in eBPF */
#define BPF_ABS  0x20  /* legacy BPF packet access (absolute)*/
#define BPF_IND  0x40  /* legacy BPF packet access (indirect)*/
#define BPF_MEM  0x60  /* regular load and store operations */
#define BPF_MEMSX  0x80  /* sign-extension load operations */
#define BPF_ATOMIC 0xc0  /*atomic operations*/

struct memmap {
    unsigned char* data = nullptr;
    size_t size = 0;
    uint64_t paddr = 0;
    uint32_t flags = 0;
    memmap() = default;
    memmap(memmap&& other) {
        data = other.data;
        size = other.size;
        paddr = other.paddr;
        flags = other.flags;
        other.data = nullptr;
        other.size = 0;
        other.flags = 0;
    }
    ~memmap();
};

struct vmOptions {
    uint64_t entry;
    bool verbose;
    uint64_t breakpoint;
    bool step_run;
    std::vector<std::string> argv;
    std::vector<std::string> envp;
};

struct fd_handle {
    const int fd = -1;
    bool cloexec = false;
    std::string path;
    explicit fd_handle(int fd, std::string path = {}) : fd(fd), path(std::move(path)) {}
    ~fd_handle();
};

class MpscQueue {
    struct slot {
        std::atomic<uint64_t> seq;
        int value = 0;
    };
    static constexpr size_t k_capacity = 1024;
    static constexpr size_t k_mask = k_capacity - 1;
    static_assert((k_capacity & (k_capacity - 1)) == 0, "k_capacity must be power of two");
    std::array<slot, k_capacity> slots{};
    std::atomic<uint64_t> head{0};
    std::atomic<uint64_t> tail{0};
public:
    MpscQueue();
    bool try_push(int value);
    bool try_pop(int& value);
    bool empty() const {
        return head.load(std::memory_order_relaxed) == tail.load(std::memory_order_relaxed);
    }
};

class vm {
    static std::atomic<uint64_t> next_pid;
    static std::unordered_map<uint64_t, std::shared_ptr<vm>> pid_map;
    static std::mutex pid_map_mutex;
    struct signal_action {
        uint64_t handler = 0;
        uint64_t mask = 0;
        int flags = 0;
    };
    vmOptions options;
    const bpf_insn* pc;
    uint64_t reg[11];
    std::list<memmap> maps;
    uint64_t pid = 0;
    std::atomic<uint64_t> ppid{0};
    pthread_t tid = 0;
    std::unordered_map<int, std::shared_ptr<fd_handle>> fds;
    std::string cwd;
    uint32_t umask_val = 0022;
    pthread_mutex_t exit_mutex;
    pthread_cond_t exit_cv;
    std::atomic<bool> exited{false};
    std::atomic<bool> stopped{false};
    std::array<signal_action, NSIG> signal_actions{};
    MpscQueue pending_signals;
    size_t signal_depth = 0;
    void* mmu(uint64_t addr);
    uint64_t unmmu(const void* addr);
    void* unmap(uint64_t addr);
    bool setup_stack(const std::vector<std::string>& argv, const std::vector<std::string>& envp);
    void log_mem_violation(const char* type, uint64_t addr);
    bool handle_pending_signals();

    bool ld();
    bool ldx();
    bool st();
    bool stx();
    bool alu();
    bool alu64();
    bool jmp();
    bool jmp32();
    bool step();

    bool read_c_string(uint64_t addr, std::string& out, size_t max_len);
    bool read_c_string_array(uint64_t addr, std::vector<std::string>& out, size_t max_count, size_t max_str_len);
    std::string resolve_path(const std::string& path) const;
    bool do_syscall(uint32_t call);
    bool do_mmap();
    bool do_munmap();
    bool do_exit();
    bool do_openat();
    bool do_read();
    bool do_write();
    bool do_lseek();
    bool do_truncate();
    bool do_ftruncate();
    bool do_close();
    bool do_unlinkat();
    bool do_renameat();
    bool do_readlink();
    bool do_execve();
    bool do_fork();
    bool do_getpid();
    bool do_getppid();
    bool do_waitpid();
    bool do_dup();
    bool do_dup2();
    bool do_pipe2();
    bool do_fstatat();
    bool do_fchmodat();
    bool do_utimensat();
    bool do_faccessat();
    bool do_kill();
    bool do_sigaction();
    bool do_fcntl();
    bool do_ioctl();
    bool do_fchdir();
    bool do_getcwd();
    bool do_fdopendir();
    bool do_readdir();
    bool do_closedir();
    bool do_mkdir();
    bool do_rmdir();
    bool do_symlinkat();
    bool do_linkat();
    bool do_umask();
    bool do_setjmp();
    bool do_longjmp();
    bool do_nanosleep();
    bool do_clock_gettime();

    struct Token { explicit Token() = default; };
public:
    vm(Token, uint64_t ppid, const std::unordered_map<int, std::shared_ptr<fd_handle>>& opened);
    ~vm();
    static std::shared_ptr<vm> create(uint64_t ppid, const std::unordered_map<int, std::shared_ptr<fd_handle>>& opened);
    bool wait_for_exit(int timeout_ms);
    uint64_t load_elf(const char* elf_file_path);
    void addmem(memmap&& memmap);
    void queue_signal(int sig);
    uint64_t& r(int n) {
        return reg[n];
    }
    bool push_frame(uint64_t return_addr, bool is_signal = false);
    uint64_t pop_frame();

    uint64_t run();
    uint64_t run(const vmOptions* options);
};


#endif //INSN_H
