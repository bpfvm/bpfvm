//
// jit_base_emitter.h — Architecture-independent code emission base.
//

#ifndef JIT_BASE_EMITTER_H
#define JIT_BASE_EMITTER_H

#include <cstdint>
#include <cstring>
#include <vector>

class EmitterBase {
protected:
    std::vector<uint8_t> buf_;

public:
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

    // Patch a Jcc rel32 at inst_offset (4-byte displacement at inst_offset+2)
    void patch_rel32(size_t inst_offset, size_t target_offset) {
        uint32_t rel = (uint32_t)(target_offset - (inst_offset + 6));
        memcpy(buf_.data() + inst_offset + 2, &rel, 4);
    }
    // Patch a JMP/CALL rel32 at inst_offset (4-byte displacement at inst_offset+1)
    void patch_jmp_rel32(size_t inst_offset, size_t target_offset) {
        uint32_t rel = (uint32_t)(target_offset - (inst_offset + 5));
        memcpy(buf_.data() + inst_offset + 1, &rel, 4);
    }
};

#endif // JIT_BASE_EMITTER_H
