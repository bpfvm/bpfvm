//===- BpfSoftFp.cpp - 虚拟 FP 指令的编码 pass ----------------------------===//
//
// 虚拟 FP 指令的设计见 include/bpf_fp.h。本 pass 在 IR 层把每个浮点运算指令替换成
// 一次对 extern __ksym 函数 `__bpf_fp_<ID>` 的调用，绕过后端在 ISel 阶段对
// fadd/fmul/... 的拒绝（"A call to built-in function '__adddf3' is not supported"）。
// FP 走 src_reg=2 通道（与 syscall 的 src_reg=0 分离），VM 解释器/JIT 直接走
// do_softfp / emit_call_softfp。
//
// 编码链路（不在 pass 里直出 src_reg=2，交给 clang 后端 + linker 协同）：
//   pass  ->  extern long __bpf_fp_<ID>(i64...) (section ".ksyms")，符号名尾部 <ID>
//            直接编码 BPF_FP_*，无映射表
//   clang ->  当普通未解析外部函数调用，按 calling convention 把参数放 r1/r2/...、结果
//            放 r0，emit `call -1`（src_reg=1 占位）+ R_BPF_64_32 重定位
//   linker->  在 R_BPF_64_32 看到 `__bpf_fp_` 符号 -> 改写 call 的 src_reg=2 + imm=<ID>
//   VM    ->  src_reg=2 的 dispatch 直达 do_softfp
//
// 寄存器绑定由后端原生 call lowering 保证（不用 InlineAsm：它的 "r"/"=r" 不保证绑
// r1/r2/r0，寄存器压力下会错放，且 clobber 会触发 LiveVariables 崩溃）。
//
// 操作数按 IEEE754 位模式当 i64 传递（fp 参数先 bitcast 到 i64；结果 i64 再 bitcast/
// trunc 回目标类型）。覆盖：算术 / fneg / sqrt / 比较 / fp<->int / fptrunc / fpext /
// fmuladd / i128 乘除模 / i128 变量移位。
//
// 用法：clang -target bpf -fpass-plugin=libBpfSoftFp.so ...
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/OptimizationLevel.h"

using namespace llvm;

namespace {

// 区分单/双精度的后缀。
static const char *suffix(Type *Ty) {
    if (Ty->isFloatTy())  return "sf";
    if (Ty->isDoubleTy()) return "df";
    return nullptr;  // 其它（long double 等）不支持
}

// ---- BPF_FP_* helper 编号：单一数据源 ----
// 直接复用 include/bpf_fp.h 的定义（BPF_FP_* enum），
// 避免在 pass 里手抄一份容易不一致的编号表。bpf_fp.h 是纯 enum，C++ 兼容。
#include "include/bpf_fp.h"

// 把一个操作数转成 i64 位模式，供 FP helper 的整数 ABI 传递：
//   - float/double：bitcast 到 i32/i64 后再 zext 到 i64（位模式原样）；
//   - 整数：zext（无符号语义；本 pass 对 int 入参都已是正确宽度，zext 不改语义）。
static Value *toI64Bits(IRBuilder<> &B, Value *V) {
    Type *Ty = V->getType();
    if (Ty->isFloatTy()) {
        V = B.CreateBitCast(V, Type::getInt32Ty(V->getContext()));
        return B.CreateZExt(V, Type::getInt64Ty(V->getContext()));
    }
    if (Ty->isDoubleTy())
        return B.CreateBitCast(V, Type::getInt64Ty(V->getContext()));
    if (Ty->isIntegerTy())
        return B.CreateZExt(V, Type::getInt64Ty(V->getContext()));
    return V;  // 已是 i64 等价物
}

// 生成一条浮点虚拟指令：对 extern __bpf_fp_<ID> 的调用（链路见文件头）。
// 操作数经 toI64Bits 转成 i64 位模式传入；结果 i64 按 RetTy 转 fp 或 trunc 回窄整数。
static Value *emitDirectFpCall(IRBuilder<> &B, LLVMContext &Ctx,
                               unsigned FpCallId,
                               ArrayRef<Value *> Args,
                               Type *RetTy) {
    Type *I64Ty = Type::getInt64Ty(Ctx);
    Module &M = *B.GetInsertBlock()->getModule();

    SmallVector<Value *, 4> I64Args;
    for (Value *A : Args)
        I64Args.push_back(toI64Bits(B, A));

    // extern __bpf_fp_<ID>(i64...) 放 .ksyms section：clang 据此 emit R_BPF_64_32
    // 重定位，linker 据符号名识别并改写 src_reg=2。
    SmallVector<Type *, 4> ArgTys(I64Args.size(), I64Ty);
    FunctionType *FTy = FunctionType::get(I64Ty, ArgTys, false);
    std::string Name = "__bpf_fp_" + std::to_string(FpCallId);
    FunctionCallee FC = M.getOrInsertFunction(Name, FTy);
    Function *F = dyn_cast<Function>(FC.getCallee());
    if (F) {
        F->setLinkage(GlobalValue::ExternalLinkage);
        if (!F->hasSection())
            F->setSection(".ksyms");
    }

    Value *Call = B.CreateCall(FC, I64Args);

    // 结果 i64 -> 目标类型。
    if (RetTy->isFloatTy())
        // float 位模式在低 32 位：i64 trunc -> i32，再 bitcast 回 float。
        return B.CreateBitCast(B.CreateTrunc(Call, Type::getInt32Ty(Ctx)), RetTy);
    if (RetTy->isDoubleTy())
        return B.CreateBitCast(Call, RetTy);
    if (RetTy->isIntegerTy() && RetTy->getIntegerBitWidth() < 64)
        return B.CreateTrunc(Call, RetTy);
    return Call;  // 已是 i64
}

// 发射 BPF_FP_UMULH（softfp 通道），取 64x64->128 的高半。用于 mul i128 与
// umul.with.overflow 的高位提取。单输出（只回 r0=hi），低半由调用方用原生 mul 另算。
static Value *emitMul128Hi(IRBuilder<> &B, LLVMContext &Ctx, Value *A, Value *Bb) {
    Type *I64Ty = Type::getInt64Ty(Ctx);
    return emitDirectFpCall(B, Ctx, BPF_FP_UMULH, {A, Bb}, I64Ty);
}

// 把 mul i128 的操作数归约成 i64。前提：操作数真值 <2^64（mul i128 在实际代码中
// 的来源——zext i64、i64 范围常量、掩码后的值——均满足）。各形态处理：
//   - zext i64->i128             -> 原 i64
//   - and i128 X, (2^k-1), k<=64  -> trunc X to i64（掩码保证值 <2^k，trunc 不丢信息）
//   - i128 常量 <=2^64-1         -> trunc to i64
//   - 其它                       -> trunc to i64（前提不成立时丢精度）
static Value *narrowToI64(IRBuilder<> &B, Value *V) {
    Type *I64Ty = Type::getInt64Ty(B.getContext());
    // zext i64->i128：直接取原值。
    if (auto *ZE = dyn_cast<ZExtInst>(V)) {
        if (ZE->getSrcTy()->isIntegerTy(64) && ZE->getDestTy()->isIntegerTy(128))
            return ZE->getOperand(0);
    }
    // and i128 X, (2^k-1)：掩码使值 <2^k<=2^64，trunc X 即正确低半。
    if (auto *BO = dyn_cast<BinaryOperator>(V)) {
        if (BO->getOpcode() == Instruction::And && BO->getType()->isIntegerTy(128)) {
            if (auto *C = dyn_cast<ConstantInt>(BO->getOperand(1))) {
                APInt Cp1 = C->getValue() + 1;          // C 是 2^k-1 <=> C+1 是 2 的幂
                if (Cp1.isPowerOf2() && Cp1.getActiveBits() <= 64) {
                    // (and X, 2^k-1) 取低 k 位。trunc 到 i64 后须【保留掩码】，
                    // 否则 X 的 bit k..63 脏数据会污染 mul 操作数。
                    Value *tr = B.CreateTrunc(BO->getOperand(0), I64Ty);
                    return B.CreateAnd(tr, ConstantInt::get(I64Ty, C->getValue().trunc(64)));
                }
            }
        }
    }
    // i128 常量（<=2^64-1）：trunc 取低半。
    if (auto *C = dyn_cast<ConstantInt>(V)) {
        if (C->getValue().getActiveBits() <= 64)
            return ConstantInt::get(I64Ty, C->getValue().trunc(64));
    }
    // 兜底：trunc。仅在 V 真值 <2^64 时正确。
    return B.CreateTrunc(V, I64Ty);
}


// 处理一个函数：把其中的浮点运算指令全部换成库调用。
static bool softenFunction(Function &F) {
    Module &M = *F.getParent();
    LLVMContext &Ctx = M.getContext();
    Type *I32Ty = Type::getInt32Ty(Ctx);

    SmallVector<Instruction *, 16> ToErase;
    bool Changed = false;

    for (BasicBlock &BB : F) {
        for (Instruction &I : make_early_inc_range(BB)) {
            IRBuilder<> B(&I);

            // ---- mul i128：后端 ISel 把它 lower 成内建 __multi3 调用，BPF 后端不支持
            // 该内建（"__multi3 not supported"）。注意这与 i128 返回值无关——lowerI128Returns
            // 改的是 IR 层用户函数的签名，管不到后端 ISel 自行生成的内建调用。操作数经
            // narrowToI64 归约成 i64（实际操作数真值均 <2^64），用 lo=原生 mul i64 +
            // hi=BPF_FP_UMULH 组装回 i128，交后端 lower 后续 add/lshr 等。
            // UMULH 只回 r0（高半），低半由原生 mul 另算——避免双输出 InlineAsm "={r1}"
            // 在 OpenSSL BN 密集乘法场景 RA 偶发丢 hi（验证）。
            if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
                if (BO->getOpcode() == Instruction::Mul &&
                    BO->getType()->isIntegerTy(128)) {
                    Value *A64 = narrowToI64(B, BO->getOperand(0));
                    Value *B64 = narrowToI64(B, BO->getOperand(1));
                    Type *I128Ty = Type::getInt128Ty(Ctx);
                    Type *I64Ty = Type::getInt64Ty(Ctx);
                    Constant *BITS64 = ConstantInt::get(I64Ty, 64);
                    Value *Lo = B.CreateMul(A64, B64);          // 低半：原生 mul i64
                    Value *Hi = emitMul128Hi(B, Ctx, A64, B64); // 高半：BPF_FP_UMULH
                    // 组装回 i128：(zext hi << 64) | zext lo。后续 add/lshr 由后端 lower。
                    Value *Prod = B.CreateOr(B.CreateShl(B.CreateZExt(Hi, I128Ty), BITS64),
                                             B.CreateZExt(Lo, I128Ty));
                    BO->replaceAllUsesWith(Prod);
                    ToErase.push_back(BO);
                    Changed = true;
                    continue;
                }
            }

            // ---- sdiv/udiv/srem/urem i128：后端 ISel lower 成内建 __divti3 等调用，
            // BPF 后端不支持（同 mul i128 / __multi3 的理由）。把两个 i128 操作数各拆成
            // (lo,hi)，调 i64 __bpf_fp_<ID>(ptr out_hi, i64 aLo, i64 aHi, i64 bLo, i64 bHi)
            //（5 参占满 BPF r1-r5）：VM 低半回 r0、高半写入 out_hi 指向的 8 字节，caller
            // 只 load 一次高半组装回 i128。不用双输出 InlineAsm（"={r1}" 在 OpenSSL BN
            // 密集乘法场景 RA 偶发丢 hi）；除法频率极低（libc++ filesystem 时间换算），
            // 高半的一次 load 可接受。JIT 无原生 lowering，回退解释器 do_softfp。
            if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
                unsigned Op = BO->getOpcode();
                unsigned FpId;
                switch (Op) {
                case Instruction::UDiv: FpId = BPF_FP_UDIV128; break;
                case Instruction::SDiv: FpId = BPF_FP_SDIV128; break;
                case Instruction::URem: FpId = BPF_FP_UREM128; break;
                case Instruction::SRem: FpId = BPF_FP_SREM128; break;
                default:                FpId = 0;              break;
                }
                if (FpId != 0 && BO->getType()->isIntegerTy(128)) {
                    Type *I128Ty = Type::getInt128Ty(Ctx);
                    Type *I64Ty = Type::getInt64Ty(Ctx);
                    Type *PtrTy = PointerType::getUnqual(Ctx);
                    Constant *BITS64 = ConstantInt::get(I64Ty, 64);
                    // 拆 (lo,hi)：操作数已是 i128，后端尚未 lower；手动 trunc 取两半。
                    auto split128 = [&](Value *V) -> std::pair<Value *, Value *> {
                        Value *Lo = B.CreateTrunc(V, I64Ty);
                        Value *Hi = B.CreateTrunc(B.CreateLShr(V, BITS64), I64Ty);
                        return {Lo, Hi};
                    };
                    auto [aLo, aHi] = split128(BO->getOperand(0));
                    auto [bLo, bHi] = split128(BO->getOperand(1));
                    // alloca 8 字节存高半。BPF 要求 alloca 在入口块（BpfSoftFp 跑在
                    // OptimizerLastEP，之后无 SROA，非入口 alloca 会被后端拒绝
                    // "unsupported dynamic stack allocation"），故用临时 builder 插入口块。
                    // 低半走 r0（正常返回值寄存器），只高半经 sret 指针——省一次 load。
                    IRBuilder<> EntryB(&F.getEntryBlock(), F.getEntryBlock().getFirstInsertionPt());
                    Value *HiSlot = EntryB.CreateAlloca(I64Ty, nullptr);
                    // 构造 extern i64 __bpf_fp_<ID>(ptr out_hi, i64 aLo, i64 aHi, i64 bLo, i64 bHi)。
                    // 返回 r0=低半，高半写入 out_hi 指向的 8 字节。
                    FunctionType *FTy = FunctionType::get(I64Ty,
                                                          {PtrTy, I64Ty, I64Ty, I64Ty, I64Ty}, false);
                    std::string Name = "__bpf_fp_" + std::to_string(FpId);
                    FunctionCallee FC = B.GetInsertBlock()->getModule()->getOrInsertFunction(Name, FTy);
                    if (Function *F = dyn_cast<Function>(FC.getCallee())) {
                        F->setLinkage(GlobalValue::ExternalLinkage);
                        if (!F->hasSection())
                            F->setSection(".ksyms");
                    }
                    Value *Lo = B.CreateCall(FC, {HiSlot, aLo, aHi, bLo, bHi});
                    Value *Hi = B.CreateLoad(I64Ty, HiSlot);
                    Value *Res = B.CreateOr(B.CreateShl(B.CreateZExt(Hi, I128Ty), BITS64),
                                            B.CreateZExt(Lo, I128Ty));
                    BO->replaceAllUsesWith(Res);
                    ToErase.push_back(BO);
                    Changed = true;
                    continue;
                }
            }

            // ---- 变量移位 i128：shl/lshr by <runtime>（后端发 __ashlti3/__lshrti3）----
            // 常量移位后端原生支持，只处理变量移位（OpenSSL 仅 f_generic 的 gf_serialize/
            // gf_deserialize 各 1 处）。把 i128 值拆成 (lo,hi)，按 K<64 / K>=64 两分支用
            // 原生 64 位变量移位实现，再组装回 i128 喂后续 or/trunc（后端原生）。
            if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
                unsigned Op = BO->getOpcode();
                if ((Op == Instruction::Shl || Op == Instruction::LShr) &&
                    BO->getType()->isIntegerTy(128) &&
                    !isa<ConstantInt>(BO->getOperand(1))) {
                    Type *I128Ty = Type::getInt128Ty(Ctx);
                    Type *I64Ty = Type::getInt64Ty(Ctx);
                    Constant *BITS64 = ConstantInt::get(I64Ty, 64);
                    // 拆 (lo,hi)：操作数已是 i128，后端尚未 lower；手动 trunc 取两半。
                    Value *X = BO->getOperand(0);
                    Value *xLo = B.CreateTrunc(X, I64Ty);
                    Value *xHi = B.CreateTrunc(B.CreateLShr(X, BITS64), I64Ty);
                    Value *k64 = B.CreateZExt(BO->getOperand(1), I64Ty);
                    Value *isSmall = B.CreateICmpULT(k64, BITS64);
                    // 交叉项里的 (64-K) 在 K==0 时等于 64，lshr/shl i64 by 64 是 poison
                    //（BPF 硬件把移位量按 6 位掩码，实测退成 >>0/<<0，把本应为 0 的交叉项
                    // 变成完整操作数）。拆成两个永不超过 63 的移位：x<>(64-K)，
                    // 因 63-K in [0,63] 恒为合法移位量，且两步合起来 == 移位 (64-K)
                    //（=64 时结果为 0，与数学语义一致）。
                    Constant *BITS63 = ConstantInt::get(I64Ty, 63);
                    Constant *ONE    = ConstantInt::get(I64Ty, 1);
                    Value *kInvM1 = B.CreateSub(BITS63, k64);   // 63-K，合法移位量
                    Value *rep = nullptr;
                    if (Op == Instruction::Shl) {
                        // K<64:  lo=xLo<<K,        hi=(xHi<<K)|(xLo>>(64-K))
                        // K>=64: lo=0,             hi=xLo<<(K-64)
                        Value *loS = B.CreateShl(xLo, k64);
                        Value *hiS = B.CreateOr(B.CreateShl(xHi, k64),
                                                B.CreateLShr(B.CreateLShr(xLo, kInvM1), ONE));
                        Value *loB = ConstantInt::get(I64Ty, 0);
                        Value *hiB = B.CreateShl(xLo, B.CreateSub(k64, BITS64));
                        Value *lo = B.CreateSelect(isSmall, loS, loB);
                        Value *hi = B.CreateSelect(isSmall, hiS, hiB);
                        rep = B.CreateOr(B.CreateShl(B.CreateZExt(hi, I128Ty), BITS64),
                                         B.CreateZExt(lo, I128Ty));
                    } else { // LShr
                        // K<64:  lo=(xLo>>K)|(xHi<<(64-K)), hi=xHi>>K
                        // K>=64: lo=xHi>>(K-64),           hi=0
                        Value *loS = B.CreateOr(B.CreateLShr(xLo, k64),
                                                B.CreateShl(B.CreateShl(xHi, kInvM1), ONE));
                        Value *hiS = B.CreateLShr(xHi, k64);
                        Value *loB = B.CreateLShr(xHi, B.CreateSub(k64, BITS64));
                        Value *hiB = ConstantInt::get(I64Ty, 0);
                        Value *lo = B.CreateSelect(isSmall, loS, loB);
                        Value *hi = B.CreateSelect(isSmall, hiS, hiB);
                        rep = B.CreateOr(B.CreateShl(B.CreateZExt(hi, I128Ty), BITS64),
                                         B.CreateZExt(lo, I128Ty));
                    }
                    BO->replaceAllUsesWith(rep);
                    ToErase.push_back(BO);
                    Changed = true;
                    continue;
                }
            }

            // ---- 二元算术：fadd/fsub/fmul/fdiv ----
            if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
                Type *Ty = BO->getType();
                const char *sfx = suffix(Ty);
                if (!sfx) continue;

                unsigned callId;
                switch (BO->getOpcode()) {
                case Instruction::FAdd: callId = sfx[0]=='d' ? BPF_FP_ADD_D : BPF_FP_ADD_F; break;
                case Instruction::FSub: callId = sfx[0]=='d' ? BPF_FP_SUB_D : BPF_FP_SUB_F; break;
                case Instruction::FMul: callId = sfx[0]=='d' ? BPF_FP_MUL_D : BPF_FP_MUL_F; break;
                case Instruction::FDiv: callId = sfx[0]=='d' ? BPF_FP_DIV_D : BPF_FP_DIV_F; break;
                default: continue;
                }
                // 参数类型与结果类型相同（fp, fp) -> fp。
                Value *Call = emitDirectFpCall(B, Ctx, callId, {BO->getOperand(0), BO->getOperand(1)}, Ty);
                // fast-math 标志不会传递（按 IEEE754 严格语义）。
                BO->replaceAllUsesWith(Call);
                ToErase.push_back(BO);
                Changed = true;
                continue;
            }

            // ---- 一元取负：fneg ----
            if (auto *UE = dyn_cast<UnaryOperator>(&I)) {
                Type *Ty = UE->getType();
                const char *sfx = suffix(Ty);
                if (!sfx) continue;
                if (UE->getOpcode() != Instruction::FNeg) continue;

                unsigned callId = sfx[0]=='d' ? BPF_FP_NEG_D : BPF_FP_NEG_F;
                Value *Call = emitDirectFpCall(B, Ctx, callId, {UE->getOperand(0)}, Ty);
                UE->replaceAllUsesWith(Call);
                ToErase.push_back(UE);
                Changed = true;
                continue;
            }

            // ---- fp -> int ----
            if (auto *CI = dyn_cast<CastInst>(&I)) {
                Type *Dst = CI->getType();
                Type *Src = CI->getOperand(0)->getType();
                Instruction::CastOps Op = CI->getOpcode();

                if (Op == Instruction::FPToSI || Op == Instruction::FPToUI) {
                    const char *sfx = suffix(Src);
                    if (!sfx) continue;
                    bool isDouble = (sfx[0] == 'd');
                    // 窄整数目标（i1/i8/i16）统一走 i32 路径（先转 i32，emitDirectFpCall
                    // 末尾 trunc 收窄），否则后端 lower 成 __fixdfsi libcall 后拒绝。
                    // 如 busybox awk.c 的 char cc = getvar_i(arg)。
                    unsigned dstBits = Dst->isIntegerTy() ? Dst->getIntegerBitWidth() : 0;
                    unsigned callId;
                    if (Op == Instruction::FPToSI) {
                        if (dstBits <= 32)             callId = isDouble ? BPF_FP_D2SI : BPF_FP_F2SI;
                        else if (dstBits == 64)        callId = isDouble ? BPF_FP_D2DI : BPF_FP_F2DI;
                        else continue;
                    } else {
                        if (dstBits <= 32)             callId = isDouble ? BPF_FP_D2USI : BPF_FP_F2USI;
                        else if (dstBits == 64)        callId = isDouble ? BPF_FP_D2UDI : BPF_FP_F2UDI;
                        else continue;
                    }
                    Value *Call = emitDirectFpCall(B, Ctx, callId, {CI->getOperand(0)}, Dst);
                    CI->replaceAllUsesWith(Call);
                    ToErase.push_back(CI);
                    Changed = true;
                    continue;
                }

                if (Op == Instruction::SIToFP || Op == Instruction::UIToFP) {
                    const char *sfx = suffix(Dst);
                    if (!sfx) continue;
                    bool isDouble = (sfx[0] == 'd');

                    // 窄整数源（i1/i8/i16）先扩展到 i32 再走 i32 路径，否则后端 lower
                    // 成 __floatunsidf libcall 后拒绝。
                    Value *SrcVal = CI->getOperand(0);
                    if (Src->isIntegerTy()) {
                        unsigned bw = Src->getIntegerBitWidth();
                        if (bw != 32 && bw != 64) {
                            Type *I32 = Type::getInt32Ty(Ctx);
                            SrcVal = (Op == Instruction::SIToFP)
                                ? B.CreateSExt(SrcVal, I32)
                                : B.CreateZExt(SrcVal, I32);
                            Src = I32;
                        }
                    }

                    unsigned callId;
                    if (Op == Instruction::SIToFP) {
                        if (Src->isIntegerTy(32))      callId = isDouble ? BPF_FP_SI2D : BPF_FP_SI2F;
                        else if (Src->isIntegerTy(64)) callId = isDouble ? BPF_FP_DI2D : BPF_FP_DI2F;
                        else continue;
                    } else {
                        if (Src->isIntegerTy(32))      callId = isDouble ? BPF_FP_USI2D : BPF_FP_USI2F;
                        else if (Src->isIntegerTy(64)) callId = isDouble ? BPF_FP_UDI2D : BPF_FP_UDI2F;
                        else continue;
                    }
                    Value *Call = emitDirectFpCall(B, Ctx, callId, {SrcVal}, Dst);
                    CI->replaceAllUsesWith(Call);
                    ToErase.push_back(CI);
                    Changed = true;
                    continue;
                }

                if (Op == Instruction::FPTrunc) {
                    // double -> float
                    if (!Src->isDoubleTy() || !Dst->isFloatTy()) continue;
                    Value *Call = emitDirectFpCall(B, Ctx, BPF_FP_TRUNC, {CI->getOperand(0)}, Dst);
                    CI->replaceAllUsesWith(Call);
                    ToErase.push_back(CI);
                    Changed = true;
                    continue;
                }

                if (Op == Instruction::FPExt) {
                    // float -> double
                    if (!Src->isFloatTy() || !Dst->isDoubleTy()) continue;
                    Value *Call = emitDirectFpCall(B, Ctx, BPF_FP_EXTEND, {CI->getOperand(0)}, Dst);
                    CI->replaceAllUsesWith(Call);
                    ToErase.push_back(CI);
                    Changed = true;
                    continue;
                }
            }

            // ---- 浮点 intrinsic：fmuladd / fma ----
            // clang 常把 `a*b+c` 收缩成 @llvm.fmuladd / @llvm.fma，必须展开后软化。
            // 这里直接发两条 BPF_FP_*（mul + add），避免新生成的 fp 指令被漏掉。
            if (auto *II = dyn_cast<IntrinsicInst>(&I)) {
                Type *Ty = II->getType();
                if (II->getIntrinsicID() == Intrinsic::fmuladd ||
                    II->getIntrinsicID() == Intrinsic::fma) {
                    const char *sfx = suffix(Ty);
                    if (!sfx) continue;
                    bool isDouble = (sfx[0] == 'd');
                    Value *A = II->getArgOperand(0);
                    Value *B_ = II->getArgOperand(1);
                    Value *C = II->getArgOperand(2);
                    unsigned mulId = isDouble ? BPF_FP_MUL_D : BPF_FP_MUL_F;
                    unsigned addId = isDouble ? BPF_FP_ADD_D : BPF_FP_ADD_F;
                    Value *Mul = emitDirectFpCall(B, Ctx, mulId, {A, B_}, Ty);
                    Value *Add = emitDirectFpCall(B, Ctx, addId, {Mul, C}, Ty);
                    II->replaceAllUsesWith(Add);
                    ToErase.push_back(II);
                    Changed = true;
                    continue;
                }
                // sqrt：VM 侧有 BPF_FP_SQRT_D/F，直接发。
                if (II->getIntrinsicID() == Intrinsic::sqrt) {
                    const char *sfx = suffix(Ty);
                    if (!sfx) continue;
                    unsigned callId = (sfx[0]=='d') ? BPF_FP_SQRT_D : BPF_FP_SQRT_F;
                    Value *Call = emitDirectFpCall(B, Ctx, callId, {II->getArgOperand(0)}, Ty);
                    II->replaceAllUsesWith(Call);
                    ToErase.push_back(II);
                    Changed = true;
                    continue;
                }
                // fabs/copysign：musl 体是单条 bitwise，会被 instcombine 折回同名 intrinsic，
                // 走 libcall 会自递归（fabs 调用自己），故保留在本 pass 走 BPF_FP_*。
                if (II->getIntrinsicID() == Intrinsic::fabs) {
                    const char *sfx = suffix(Ty);
                    if (!sfx) continue;
                    unsigned callId = (sfx[0]=='d') ? BPF_FP_FABS_D : BPF_FP_FABS_F;
                    Value *Call = emitDirectFpCall(B, Ctx, callId, {II->getArgOperand(0)}, Ty);
                    II->replaceAllUsesWith(Call);
                    ToErase.push_back(II);
                    Changed = true;
                    continue;
                }
                if (II->getIntrinsicID() == Intrinsic::copysign) {
                    const char *sfx = suffix(Ty);
                    if (!sfx) continue;
                    unsigned callId = (sfx[0]=='d') ? BPF_FP_COPYSIGN_D : BPF_FP_COPYSIGN_F;
                    Value *Call = emitDirectFpCall(B, Ctx, callId,
                        {II->getArgOperand(0), II->getArgOperand(1)}, Ty);
                    II->replaceAllUsesWith(Call);
                    ToErase.push_back(II);
                    Changed = true;
                    continue;
                }
                // umul.with.overflow（__builtin_mul_overflow 的 IR 形态）：用
                // Lo = 原生 BPF_MUL 截断 + Hi = BPF_FP_UMULH 展开，按 {i64,i1}
                // 语义重写 extractvalue：index 0->Lo，index 1->Ov(=Hi!=0)。
                // 注意：II->getType() 是 {i64,i1} struct，不能用 suffix(Ty) 判断
                // （会返回 nullptr 漏过），必须用 operand 类型判断。只处理 i64 重载；
                // i32 等窄类型 BPF 原生支持，留给后端。
                if (II->getIntrinsicID() == Intrinsic::umul_with_overflow) {
                    Type *OpTy = II->getArgOperand(0)->getType();
                    if (!OpTy->isIntegerTy(64)) continue;

                    Value *A  = II->getArgOperand(0);
                    Value *Bb = II->getArgOperand(1);
                    Value *Lo = B.CreateMul(A, Bb);                          // 低位：原生 mul i64
                    Value *Hi = emitMul128Hi(B, Ctx, A, Bb);                 // 高位：BPF_FP_UMULH
                    Value *Ov = B.CreateICmpNE(Hi, ConstantInt::get(OpTy, 0)); // 溢出 = 高位非零

                    SmallVector<User *, 4> Users(II->user_begin(), II->user_end());
                    for (User *U : Users) {
                        auto *EV = dyn_cast<ExtractValueInst>(U);
                        if (!EV) continue;   // 罕见非 extractvalue user，留给后端
                        Value *Rep = (EV->getNumIndices() && EV->getIndices()[0] == 1) ? Ov : Lo;
                        EV->replaceAllUsesWith(Rep);
                        ToErase.push_back(EV);
                    }
                    ToErase.push_back(II);
                    Changed = true;
                    continue;
                }
            }

            // ---- sqrt/fabs/copysign libcall 拦截 -> VM 虚拟指令 ----
            // （源码直接调 sqrt()/fabsf()，或 libc++ 头里的 sqrt）。
            if (auto *CI = dyn_cast<CallInst>(&I)) {
                Function *Callee = CI->getCalledFunction();
                if (Callee && !Callee->isIntrinsic()) {
                    StringRef Name = Callee->getName();
                    unsigned idD = 0, idF = 0;
                    bool binary = false;
                    if (Name == "sqrt" || Name == "sqrtf") { idD = BPF_FP_SQRT_D; idF = BPF_FP_SQRT_F; }
                    else if (Name == "fabs" || Name == "fabsf") { idD = BPF_FP_FABS_D; idF = BPF_FP_FABS_F; }
                    else if (Name == "copysign" || Name == "copysignf") { idD = BPF_FP_COPYSIGN_D; idF = BPF_FP_COPYSIGN_F; binary = true; }
                    if (idD != 0) {
                        Type *RetTy = CI->getType();
                        const char *sfx = suffix(RetTy);
                        if (sfx) {
                            unsigned callId = (sfx[0]=='d') ? idD : idF;
                            SmallVector<Value*, 2> args;
                            for (Use &A : CI->args()) args.push_back(toI64Bits(B, A.get()));
                            (void)binary;
                            Value *Call = emitDirectFpCall(B, Ctx, callId, args, RetTy);
                            CI->replaceAllUsesWith(Call);
                            ToErase.push_back(CI);
                            Changed = true;
                            continue;
                        }
                    }
                }
            }

            // ---- 比较：fcmp ----
            // 三态 CMP（<0/=0/>0）丢失了 NaN 信息：无法区分"相等(==0)"与"NaN 无法
            // 比较(也落到 ==0)"。故配合独立的 UNORD（任一 NaN->1，否则->0）精确还原
            // 每个 IEEE754 谓词：有序谓词 && !uno，无序谓词 || uno。
            if (auto *FCmp = dyn_cast<FCmpInst>(&I)) {
                Type *Ty = FCmp->getOperand(0)->getType();
                const char *sfx = suffix(Ty);
                if (!sfx) continue;

                const bool is_d = sfx[0]=='d';
                unsigned cmpId   = is_d ? BPF_FP_CMP_D   : BPF_FP_CMP_F;
                unsigned unordId = is_d ? BPF_FP_UNORD_D : BPF_FP_UNORD_F;
                Value *Op0 = FCmp->getOperand(0);
                Value *Op1 = FCmp->getOperand(1);
                Value *Zero = ConstantInt::get(I32Ty, 0);

                // 按谓词按需发射 helper：CMP 仅 <,>,=,!= 需要；UNORD 仅非常量谓词需要。
                auto EmitCmp   = [&]() { return emitDirectFpCall(B, Ctx, cmpId,   {Op0, Op1}, I32Ty); };
                auto EmitUnord = [&]() { return emitDirectFpCall(B, Ctx, unordId, {Op0, Op1}, I32Ty); };

                CmpInst::Predicate pred = FCmp->getPredicate();
                Value *Result = nullptr;
                switch (pred) {
                case FCmpInst::FCMP_FALSE:
                    Result = ConstantInt::getFalse(Ctx); break;
                case FCmpInst::FCMP_TRUE:
                    Result = ConstantInt::getTrue(Ctx); break;
                case FCmpInst::FCMP_ORD:                  // 有序：都不是 NaN
                    Result = B.CreateICmpEQ(EmitUnord(), Zero); break;
                case FCmpInst::FCMP_UNO:                  // 无序：至少一个 NaN
                    Result = B.CreateICmpNE(EmitUnord(), Zero); break;
                default: break;   // 六组二元比较在下面统一处理
                }
                if (!Result) {
                    // Cmp 三态 -> 有序比较结果；Uno -> 是否无序(NaN)。
                    Value *Cmp   = EmitCmp();
                    Value *Uno   = EmitUnord();
                    Value *isUno = B.CreateICmpNE(Uno, Zero);       // 无序
                    Value *isOrd = B.CreateICmpEQ(Uno, Zero);        // 有序
                    Value *ordCmp = nullptr;   // 不考虑 NaN 时的比较结果
                    switch (pred) {
                    case FCmpInst::FCMP_OLT: case FCmpInst::FCMP_ULT:
                        ordCmp = B.CreateICmpSLT(Cmp, Zero); break;
                    case FCmpInst::FCMP_OGT: case FCmpInst::FCMP_UGT:
                        ordCmp = B.CreateICmpSGT(Cmp, Zero); break;
                    case FCmpInst::FCMP_OEQ: case FCmpInst::FCMP_UEQ:
                        ordCmp = B.CreateICmpEQ(Cmp, Zero); break;
                    case FCmpInst::FCMP_ONE: case FCmpInst::FCMP_UNE:
                        ordCmp = B.CreateICmpNE(Cmp, Zero); break;
                    case FCmpInst::FCMP_OLE: case FCmpInst::FCMP_ULE:
                        ordCmp = B.CreateICmpSLE(Cmp, Zero); break;
                    case FCmpInst::FCMP_OGE: case FCmpInst::FCMP_UGE:
                        ordCmp = B.CreateICmpSGE(Cmp, Zero); break;
                    default:
                        ordCmp = B.CreateICmpNE(Cmp, Zero); break;
                    }
                    // O 前缀（有序）：NaN 时强制 false。U 前缀（无序）：NaN 时强制 true。
                    bool isUnorderedPred = (pred == FCmpInst::FCMP_ULT ||
                                           pred == FCmpInst::FCMP_UGT ||
                                           pred == FCmpInst::FCMP_UEQ ||
                                           pred == FCmpInst::FCMP_UNE ||
                                           pred == FCmpInst::FCMP_ULE ||
                                           pred == FCmpInst::FCMP_UGE);
                    Result = isUnorderedPred
                        ? B.CreateOr(ordCmp, isUno)
                        : B.CreateAnd(ordCmp, isOrd);
                }
                FCmp->replaceAllUsesWith(Result);
                ToErase.push_back(FCmp);
                Changed = true;
                continue;
            }

            // ---- 其它 fp intrinsic（fabs/copysign/...）留待后续 ----
        }
    }

    // 统一回收被替换的指令。
    for (Instruction *I : ToErase)
        I->eraseFromParent();

    return Changed;
}

class BpfSoftFpPass : public PassInfoMixin<BpfSoftFpPass> {
public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        if (F.isDeclaration())
            return PreservedAnalyses::all();
        // 跳过编译器自带的软浮点库函数（__adddf3 等），否则在它们内部无限递归改写。
        if (isSoftFpRuntimeFunc(F.getName()))
            return PreservedAnalyses::all();
        return softenFunction(F) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

private:
    // libgcc/compiler-rt 软浮点 runtime 函数全集（sf=单精度，df=双精度，tf=quad，
    // xf=80-bit）。精确匹配整名，不能用 starts_with("__float")——会误伤 musl 的
    // __floatscan/__floatundisf 等同名前缀函数。
    static bool isSoftFpRuntimeFunc(StringRef Name) {
        static const char *const SoftFpFuncs[] = {
            "__addsf3", "__adddf3", "__addtf3", "__addxf3",
            "__subsf3", "__subdf3", "__subtf3", "__subxf3",
            "__mulsf3", "__muldf3", "__multf3", "__mulxf3",
            "__divsf3", "__divdf3", "__divtf3", "__divxf3",
            "__negsf2", "__negdf2", "__negtf2", "__negxf2",
            "__sqrtf", "__sqrt", "__sqrttf2",
            "__fixsfsi", "__fixsfdi", "__fixsfti",
            "__fixdfsi", "__fixdfdi", "__fixdfti",
            "__fixtfsi", "__fixtfdi", "__fixtfti",
            "__fixxfsi", "__fixxfdi", "__fixxfti",
            "__fixunssfsi", "__fixunssfdi", "__fixunssfti",
            "__fixunsdfsi", "__fixunsdfdi", "__fixunsdfti",
            "__fixunstfsi", "__fixunstfdi", "__fixunstfti",
            "__fixunsxfsi", "__fixunsxfdi", "__fixunsxfti",
            "__floatsisf", "__floatdisf", "__floattisf",
            "__floatsidf", "__floatdidf", "__floattidf",
            "__floatsitf", "__floatditf", "__floattitf",
            "__floatsixf", "__floatdixf", "__floattixf",
            "__floatunsisf", "__floatundisf", "__floatuntisf",
            "__floatunsidf", "__floatundidf", "__floatuntidf",
            "__floatunsitf", "__floatunditf", "__floatuntitf",
            "__floatunsixf", "__floatundixf", "__floatuntixf",
            "__extendsfdf2", "__extendsftf2", "__extendsfxf2",
            "__truncdfsf2", "__trunctfsf2", "__truncxfsf2",
            "__trunctfdf2", "__truncxfdf2",
            "__extenddftf2", "__extenddfxf2",
            "__eqsf2", "__nesf2", "__ltsf2", "__gtsf2", "__lesf2", "__gesf2",
            "__eqdf2", "__nedf2", "__ltdf2", "__gtdf2", "__ledf2", "__gedf2",
            "__eqtf2", "__netf2", "__lttf2", "__gttf2", "__letf2", "__getf2",
            "__eqxf2", "__nexf2", "__ltxf2", "__gtxf2", "__lexf2", "__gexf2",
            "__unordsf2", "__unorddf2", "__unordtf2", "__unordxf2",
            "__multi3",
        };
        for (const char *S : SoftFpFuncs)
            if (Name == S)
                return true;
        return false;
    }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "BpfSoftFp", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                // 必须在常量折叠/instcombine 之后：否则会把浮点常量表达式（如 VLA
                // 长度计算）替换成运行时 call，使其不再可折叠，导致 VLA 退化成真
                // 动态栈分配被后端拒绝。放到优化器末尾，只软化剩下的真运行时浮点指令。
                auto addPass = [](ModulePassManager &MPM) {
                    FunctionPassManager FPM;
                    FPM.addPass(BpfSoftFpPass());
                    MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
                };
                PB.registerOptimizerLastEPCallback(
#if LLVM_VERSION_MAJOR >= 21
                    [addPass](ModulePassManager &MPM, OptimizationLevel, ThinOrFullLTOPhase) {
#else
                    [addPass](ModulePassManager &MPM, OptimizationLevel) {
#endif
                        addPass(MPM);
                    });
                // -O0 没有 optimizer 阶段，在 PipelineStartEP 跑（-O0 不做常量折叠，
                // 无上述风险）。
                PB.registerPipelineStartEPCallback(
                    [addPass](ModulePassManager &MPM, OptimizationLevel OL) {
                        if (OL == OptimizationLevel::O0)
                            addPass(MPM);
                    });
            }};
}
