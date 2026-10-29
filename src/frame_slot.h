// 函数入口帧槽：bpfvm-ld 在每个可执行 section 头部插入 8 字节
// [magic32 | frame_size32]，位于段首函数（-ffunction-sections 下即唯一函数）
// 入口地址 -8 处。VM 的 push_frame / JIT 的直接调用序列在此读该函数的
// 编译期栈帧大小（-fstack-size-section 的 .stack_sizes 值），取代全局
// -S/--stack-limit 每帧等量预留。
#pragma once
#include <cstdint>

constexpr uint64_t FRAME_SLOT_MAGIC = 0x6270766DULL;     // "bpvm"
// 槽低 32 位为帧大小，槽编码独立于 frame[0] 的 24 位字段。
// 合法帧大小 < STACK_SIZE <= 2^24，0xFFFFFFFF 不可能是真实值，可作 FALLBACK 标记。
constexpr uint64_t FRAME_SLOT_SIZE_MASK = 0xFFFFFFFFull;
constexpr uint64_t FRAME_SLOT_FALLBACK = 0xFFFFFFFFULL;

constexpr uint64_t make_frame_slot(uint64_t frame_size) {
    return (FRAME_SLOT_MAGIC << 32) | frame_size;
}
