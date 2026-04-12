//
// jit_base_emitter.h — Architecture-independent code emission base.
//

#ifndef JIT_BASE_EMITTER_H
#define JIT_BASE_EMITTER_H

#include <cstdint>
#include <cstring>
#include <vector>
#include "jit.h"

class EmitterBase {
protected:
    std::vector<uint8_t> buf_;

    // VM field offsets (set via set_vm_offsets)
    size_t off_reg_ = 0;
    size_t off_pc_ = 0;
    size_t off_flags_ = 0;
    size_t off_tlb_ = 0;

    // Helper function pointers (set via set_helpers)
    HelperTable helpers_;

    // vm_exit offset (set by emit_prologue, used by all emit_* methods)
    size_t vm_exit_offset = 0;

public:
    // --- Byte emission ---
    void emit8(uint8_t v) { buf_.push_back(v); }
    void emit16(uint16_t v) {
        buf_.push_back(v & 0xFF);
        buf_.push_back((v >> 8) & 0xFF);
    }
    void emit32(uint32_t v) {
        buf_.push_back(v & 0xFF);
        buf_.push_back((v >> 8) & 0xFF);
        buf_.push_back((v >> 16) & 0xFF);
        buf_.push_back((v >> 24) & 0xFF);
    }
    void emit64(uint64_t v) {
        emit32((uint32_t)v);
        emit32((uint32_t)(v >> 32));
    }

    size_t size() const { return buf_.size(); }
    uint8_t* data() { return buf_.data(); }

    // --- VM state setup (call before each compilation session) ---
    void set_vm_offsets(size_t off_reg, size_t off_pc, size_t off_flags, size_t off_tlb) {
        off_reg_ = off_reg; off_pc_ = off_pc; off_flags_ = off_flags; off_tlb_ = off_tlb;
    }
    void set_helpers(const HelperTable& h) { helpers_ = h; }
};

#endif // JIT_BASE_EMITTER_H
