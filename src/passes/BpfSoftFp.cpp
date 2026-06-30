//===- BpfSoftFp.cpp - 虚拟 FP 指令的编码 pass ----------------------------===//
//
// 虚拟 FP 指令的设计见 include/bpf_call.h（bpf_fp_op enum 段注释）。本 pass
// 负责编码阶段：在 IR 层把每个浮点运算指令替换成一次对 extern __ksym 函数
// `__bpf_fp_<ID>` 的调用，绕过后端在 ISel 阶段对 fadd/fmul/... 的拒绝
// （"A call to built-in function '__adddf3' is not supported"）。
//
// 语义目标：FP 走 src_reg=2 的"浮点专用通道"，与 syscall（src_reg=0）彻底分离。
// VM 解释器/JIT 看到 src_reg=2 直接走 do_softfp / emit_call_softfp，不经过
// syscall handler。字节码层一眼能区分 FP（call src_reg=2）与 syscall（src_reg=0）。
//
// 编码链路（不在 pass 里直出 src_reg=2，交给 clang 后端 + linker 协同）：
//   1. pass 把 fadd/... 改成 `call @__bpf_fp_<ID>(i64...)`（extern，section
//      ".ksyms"）。符号名尾部 <ID> 直接编码 BPF_FP_*，无映射表。
//   2. clang 后端把它当作普通未解析外部函数调用：按 calling convention 把参数
//      放 r1/r2、结果放 r0，emit `call -1`（src_reg=1 占位）+ R_BPF_64_32 重定位
//      （目标符号 = __bpf_fp_<ID>）。参数/结果的寄存器绑定由后端原生 call lowering
//      保证（这是 InlineAsm 方案做不到的：InlineAsm 的 "r"/"=r" 不保证绑 r1/r2/r0，
//      在寄存器压力下会错放，且 clobber 会触发 LiveVariables 崩溃，故弃用）。
//   3. bpfvm-ld 在 R_BPF_64_32 看到 `__bpf_fp_` 符号：解析名字尾的 ID，改写 call
//      的 src_reg=2 + imm=<ID>，且不报"未定义符号"（VM 按 src_reg=2 解释）。
//
// 操作数按 IEEE754 位模式当 i64 传递（fp 参数先 bitcast 到 i64；结果 i64 再按
// 需 bitcast/trunc 回目标类型）。覆盖：算术 / fneg / sqrt / 比较 /
// fp<->int / fptrunc / fpext / fmuladd。
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
// 直接复用 include/bpf_call.h 的定义（BPF_CALL_BASE + BPF_FP_* 宏），
// 避免在 pass 里手抄一份容易不一致的编号表。bpf_call.h 是纯宏/enum，C++ 兼容。
#include "include/bpf_call.h"

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

// 生成一条浮点虚拟指令：一次对 extern __ksym 函数的调用。
//
// 编码链路：
//   pass  →  extern long __bpf_fp_<ID>(i64...) (section ".ksyms")
//   clang →  `call -1`（src_reg=1，PC-relative 占位）+ R_BPF_64_32 重定位
//            （目标符号 = `__bpf_fp_<ID>`）
//   linker→  识别 `__bpf_fp_` 符号 → 改写 call 的 src_reg=2、imm=<ID>，
//            且不报"未定义符号"（这些符号由 VM 在运行时按 src_reg=2 解释）
//   VM    →  src_reg=2 的 dispatch 直达 do_softfp（与 syscall 彻底分离）
//
// 寄存器绑定（关键稳定性来源）：
//   这是一次"普通外部函数调用"，clang BPF 后端按 calling convention 处理——
//   参数自动落 r1/r2/...、结果回 r0。这是后端原生 call lowering 保证的，
//   不依赖 InlineAsm 的约束赌博（InlineAsm 方案实测在寄存器压力下会把一元 op
//   的输入错放到 r2，且 clobber 会触发 LiveVariables 崩溃，已弃用）。
//
// 符号名编码 ID（无映射表）：
//   符号名 `__bpf_fp_<ID>` 直接携带 FP_ID，linker 解析名字尾部数字即得 ID，
//   pass 造名 / linker 解名是单向数据流，无需两侧维护同步的查表。
//
// 操作数与结果统一按 i64 位模式传递（toI64Bits 入，按 RetTy 出）：
//   fp 结果：i64 bitcast 回 float/double；
//   int 结果（如 CMP 的 i32）：i64 trunc 回目标宽度。
static Value *emitDirectFpCall(IRBuilder<> &B, LLVMContext &Ctx,
                               unsigned FpCallId,
                               ArrayRef<Value *> Args,
                               Type *RetTy) {
    Type *I64Ty = Type::getInt64Ty(Ctx);
    Module &M = *B.GetInsertBlock()->getModule();

    // 入参全部转成 i64 位模式。
    SmallVector<Value *, 4> I64Args;
    for (Value *A : Args)
        I64Args.push_back(toI64Bits(B, A));

    // 构造 extern 函数声明：(i64)(i64, i64, ...)，符号名 __bpf_fp_<ID>，
    // 放 .ksyms section（让 clang emit R_BPF_64_32 重定位，linker 据符号名识别）。
    SmallVector<Type *, 4> ArgTys(I64Args.size(), I64Ty);
    FunctionType *FTy = FunctionType::get(I64Ty, ArgTys, false);
    std::string Name = "__bpf_fp_" + std::to_string(FpCallId);
    FunctionCallee FC = M.getOrInsertFunction(Name, FTy);
    Function *F = dyn_cast<Function>(FC.getCallee());
    if (F) {
        F->setLinkage(GlobalValue::ExternalLinkage);
        // section 名与内核 libbpf 的 kfunc（extern __ksym）约定一致；
        // clang 据此 emit R_BPF_64_32 重定位（src_reg=1 的未解析 call）。
        if (!F->hasSection())
            F->setSection(".ksyms");
    }

    // 普通函数调用：clang 后端按 calling convention 把参数放 r1/r2、结果放 r0，
    // 并 emit `call -1` + R_BPF_64_32（指向 __bpf_fp_<ID>）。
    Value *Call = B.CreateCall(FC, I64Args);

    // 结果 i64 → 目标类型。
    if (RetTy->isFloatTy())
        // float 位模式在低 32 位：i64 trunc → i32，再 bitcast 回 float。
        return B.CreateBitCast(B.CreateTrunc(Call, Type::getInt32Ty(Ctx)), RetTy);
    if (RetTy->isDoubleTy())
        return B.CreateBitCast(Call, RetTy);
    if (RetTy->isIntegerTy() && RetTy->getIntegerBitWidth() < 64)
        return B.CreateTrunc(Call, RetTy);
    return Call;  // 已是 i64
}

// 计算 64×64→128 无符号乘法的高 64 位（schoolbook 展开）。
//
// 用于拦截 @llvm.umul.with.overflow.i64：后端会把该 intrinsic lower 成 __multi3
// 调用，BPF ISel 一律拒绝（"__multi3 not supported"）。这里在 IR 层用 4 次
// 32×32 BPF_MUL + 移位/加法构造高位，纯原生 ALU，零递归触发宽乘。
//
// 数学推导（aH/aL/bH/bL 均为 32 位）：
//   a*b = (aH*bH)<<64 + (aH*bL + aL*bH)<<32 + aL*bL
//   高 64 = aH*bH + ((aH*bL + aL*bH) + (aL*bL >> 32)) >> 32
//         = aH*bH + (cross + carry_LL) >> 32
// 32×32→64 乘法对 BPF BPF_MUL 是原生操作（操作数掩码到 32 位，乘积完整落在 64 位）。
static Value *emitUmulHi64(IRBuilder<> &B, LLVMContext &Ctx, Value *A, Value *Bb) {
    Type *I64Ty = Type::getInt64Ty(Ctx);
    Constant *MASK32 = ConstantInt::get(I64Ty, 0xFFFFFFFFULL);
    Constant *BITS32 = ConstantInt::get(I64Ty, 32);

    Value *aL = B.CreateAnd(A,  MASK32);
    Value *aH = B.CreateLShr(A, BITS32);
    Value *bL = B.CreateAnd(Bb, MASK32);
    Value *bH = B.CreateLShr(Bb, BITS32);

    Value *LL    = B.CreateMul(aL, bL);                    // aL*bL (32x32->64)
    Value *t1    = B.CreateMul(aH, bL);                    // aH*bL
    Value *t2    = B.CreateMul(aL, bH);                    // aL*bH
    Value *cross = B.CreateAdd(B.CreateAdd(t1, t2),
                               B.CreateLShr(LL, BITS32));  // cross + LL>>32
    Value *hi    = B.CreateAdd(B.CreateMul(aH, bH),
                               B.CreateLShr(cross, BITS32)); // aH*bH + cross>>32
    return hi;
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

            // ---- fp → int ----
            if (auto *CI = dyn_cast<CastInst>(&I)) {
                Type *Dst = CI->getType();
                Type *Src = CI->getOperand(0)->getType();
                Instruction::CastOps Op = CI->getOpcode();

                if (Op == Instruction::FPToSI || Op == Instruction::FPToUI) {
                    const char *sfx = suffix(Src);
                    if (!sfx) continue;
                    bool isDouble = (sfx[0] == 'd');
                    unsigned callId;
                    if (Op == Instruction::FPToSI) {
                        if (Dst->isIntegerTy(32))      callId = isDouble ? BPF_FP_D2SI : BPF_FP_F2SI;
                        else if (Dst->isIntegerTy(64)) callId = isDouble ? BPF_FP_D2DI : BPF_FP_F2DI;
                        else continue;
                    } else {
                        if (Dst->isIntegerTy(32))      callId = isDouble ? BPF_FP_D2USI : BPF_FP_F2USI;
                        else if (Dst->isIntegerTy(64)) callId = isDouble ? BPF_FP_D2UDI : BPF_FP_F2UDI;
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
                    Value *Call = emitDirectFpCall(B, Ctx, callId, {CI->getOperand(0)}, Dst);
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
                // umul.with.overflow：__builtin_mul_overflow(uint64_t,...) 的 IR 形态。
                // 后端会 lower 成 __multi3 调用，BPF ISel 一律拒绝。这里在 IR 层展开成
                // schoolbook 32×32 ALU（Lo = 原生 BPF_MUL 截断，Hi = emitUmulHi64），
                // 并按 {i64,i1} 语义重写 extractvalue users：index 0→Lo，index 1→Ov。
                // 注意：II->getType() 是 {i64,i1} struct，不能用 suffix(Ty) 判断
                // （会返回 nullptr 漏过），必须用 operand 类型判断。只处理 i64 重载
                // （现实 __multi3 唯一来源）；i32 等窄类型 BPF 原生支持，留给后端。
                if (II->getIntrinsicID() == Intrinsic::umul_with_overflow) {
                    Type *OpTy = II->getArgOperand(0)->getType();
                    if (!OpTy->isIntegerTy(64)) continue;

                    Value *A  = II->getArgOperand(0);
                    Value *Bb = II->getArgOperand(1);
                    Value *Lo = B.CreateMul(A, Bb);                               // 低位：原生 BPF_MUL
                    Value *Hi = emitUmulHi64(B, Ctx, A, Bb);                       // 高位：schoolbook
                    Value *Ov = B.CreateICmpNE(Hi, ConstantInt::get(OpTy, 0));     // 溢出 = 高位非零

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
                // fabs / copysign / minnum / maxnum / floor / ceil / trunc / rint / nearbyint
                // 暂不支持，保留（极少触发）。后续可按需补充。
            }

            // ---- 比较：fcmp ----
            // 三态 CMP（<0/=0/>0）丢失了 NaN 信息：无法区分"相等(==0)"与"NaN 无法
            // 比较(也落到 ==0)"。故配合独立的 UNORD（任一 NaN→1，否则→0）精确还原
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
                    // Cmp 三态 → 有序比较结果；Uno → 是否无序(NaN)。
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
        // 不要软化编译器自带的软浮点库函数（如 __adddf3/__floatsidf/__fixdfdi 等），
        // 否则会在它们内部无限递归改写。这里用精确后缀判断：这些 runtime helper
        // 的命名是 libgcc/compiler-rt 的固定集合，特征是「名字里含 sf/df 且以
        // 数字 2/3 结尾」（如 __adddf3、__floatsidf、__extendsfdf2、__unorddf2）。
        // 注意不能用 starts_with("__float") 之类——会误伤 musl 内部的
        // __floatscan/__floatundisf 等同名前缀函数。
        if (isSoftFpRuntimeFunc(F.getName()))
            return PreservedAnalyses::all();
        return softenFunction(F) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

private:
    static bool isSoftFpRuntimeFunc(StringRef Name) {
        // libgcc / compiler-rt 软浮点 runtime 函数全集（sf=单精度，df=双精度，
        // tf=long double/quad，xf=80-bit）。命名约定见 GCC manual「Statements that
        // affect the runtime」与 LLVM lib/builtins。
        static const char *const SoftFpFuncs[] = {
            // 算术
            "__addsf3", "__adddf3", "__addtf3", "__addxf3",
            "__subsf3", "__subdf3", "__subtf3", "__subxf3",
            "__mulsf3", "__muldf3", "__multf3", "__mulxf3",
            "__divsf3", "__divdf3", "__divtf3", "__divxf3",
            // 一元
            "__negsf2", "__negdf2", "__negtf2", "__negxf2",
            "__sqrtf", "__sqrt", "__sqrttf2",
            // fp -> int (fix)
            "__fixsfsi", "__fixsfdi", "__fixsfti",
            "__fixdfsi", "__fixdfdi", "__fixdfti",
            "__fixtfsi", "__fixtfdi", "__fixtfti",
            "__fixxfsi", "__fixxfdi", "__fixxfti",
            "__fixunssfsi", "__fixunssfdi", "__fixunssfti",
            "__fixunsdfsi", "__fixunsdfdi", "__fixunsdfti",
            "__fixunstfsi", "__fixunstfdi", "__fixunstfti",
            "__fixunsxfsi", "__fixunsxfdi", "__fixunsxfti",
            // int -> fp (float)
            "__floatsisf", "__floatdisf", "__floattisf",
            "__floatsidf", "__floatdidf", "__floattidf",
            "__floatsitf", "__floatditf", "__floattitf",
            "__floatsixf", "__floatdixf", "__floattixf",
            "__floatunsisf", "__floatundisf", "__floatuntisf",
            "__floatunsidf", "__floatundidf", "__floatuntidf",
            "__floatunsitf", "__floatunditf", "__floatuntitf",
            "__floatunsixf", "__floatundixf", "__floatuntixf",
            // 类型转换
            "__extendsfdf2", "__extendsftf2", "__extendsfxf2",
            "__truncdfsf2", "__trunctfsf2", "__truncxfsf2",
            "__trunctfdf2", "__truncxfdf2",
            "__extenddftf2", "__extenddfxf2",
            // 比较
            "__eqsf2", "__nesf2", "__ltsf2", "__gtsf2", "__lesf2", "__gesf2",
            "__eqdf2", "__nedf2", "__ltdf2", "__gtdf2", "__ledf2", "__gedf2",
            "__eqtf2", "__netf2", "__lttf2", "__gttf2", "__letf2", "__getf2",
            "__eqxf2", "__nexf2", "__ltxf2", "__gtxf2", "__lexf2", "__gexf2",
            "__unordsf2", "__unorddf2", "__unordtf2", "__unordxf2",
            // 杂项
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
                // 运行时机很重要：必须在常量折叠 / instcombine 之后。
                // 若跑在管道起始处，会把 max_int_length() 里 (bytes*8-1)*0.301+14
                // 这种浮点常量表达式替换成运行时 call，使其不再可被前端折叠，
                // 导致依赖它做 VLA 长度的代码（dash expand.c: char buf[len]）
                // 变成真 VLA，被 BPF 后端拒绝（"unsupported dynamic stack allocation"）。
                // 放到优化器末尾：此时该折叠的常量已折叠成 ConstantFP/常量，本 pass
                // 只软化剩下的真运行时浮点指令。
                auto addPass = [](ModulePassManager &MPM) {
                    FunctionPassManager FPM;
                    FPM.addPass(BpfSoftFpPass());
                    MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
                };
                // 有优化的级别（-O1+）：走 optimizer 末尾。
                // LLVM >= 21 给 OptimizerLastEPCallback 增加了 ThinOrFullLTOPhase 形参。
                PB.registerOptimizerLastEPCallback(
#if LLVM_VERSION_MAJOR >= 21
                    [addPass](ModulePassManager &MPM, OptimizationLevel OL,
                              ThinOrFullLTOPhase) {
#else
                    [addPass](ModulePassManager &MPM, OptimizationLevel OL) {
#endif
                        addPass(MPM);
                    });
                // -O0：没有 optimizer 阶段，只能在管道起始跑。
                // -O0 不做常量折叠，VLA 本身也不会退化，故无上述风险。
                PB.registerPipelineStartEPCallback(
                    [addPass](ModulePassManager &MPM, OptimizationLevel OL) {
                        if (OL == OptimizationLevel::O0)
                            addPass(MPM);
                    });
            }};
}
