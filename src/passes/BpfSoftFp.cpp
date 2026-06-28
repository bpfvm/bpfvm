//===- BpfSoftFp.cpp - 虚拟 FP 指令的编码 pass ----------------------------===//
//
// 虚拟 FP 指令的设计见 include/bpf_call.h（BPF_SYS_FP_BASE 段注释）。本 pass
// 负责编码阶段：在 IR 层把每个浮点运算指令替换成一条对应的 BPF_CALL_FP_*
// 直接调用（inttoptr），后端 lower 成 `call <imm>`（src_reg=0），绕过后端在
// ISel 阶段对 fadd/fmul/... 的拒绝（"A call to built-in function '__adddf3'
// is not supported"）。
//
// 关键选择：走 syscall 形式（src_reg=0）而非 `call __adddf3` 库函数（src_reg=1
// 的 BPF-to-BPF 调用）。后者会强制 VM exit、打断 JIT；src_reg=0 的 call 是 JIT
// 能当作单条指令内联执行的唯一 call 形式。无 guest 侧 glue。
//
// 操作数按 IEEE754 位模式当 i64 传递。覆盖：算术 / fneg / sqrt / 比较 /
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

// ---- BPF_CALL_FP_* helper 编号：单一数据源 ----
// 直接复用 include/bpf_call.h 的定义（BPF_CALL_BASE + BPF_CALL_FP_* 宏），
// 避免在 pass 里手抄一份容易不一致的编号表。bpf_call.h 是纯宏/enum，C++ 兼容。
// clang 把 inttoptr(i64 BPF_CALL_FP_*) 的调用编成 `call <imm>`（src_reg=0）。
#include "include/bpf_call.h"

// 生成一条"直接 syscall 形式"的浮点调用：
//   result = ((RetTy (*)(ArgTys...)) <FP call id>)(args...)
// 经 BPF 后端编成 `call <imm>`（src_reg=0），VM 侧由 do_softfp 用宿主浮点执行，
// JIT 侧可在此识别 imm 直接发原生指令。
//
// 函数指针签名的参数类型表取各 Args 自身的类型——对 fp<->int 转换（参数是 fp、
// 返回是 int，或反之）同样精确，无需额外传入。
static Value *emitDirectFpCall(IRBuilder<> &B, LLVMContext &Ctx,
                               unsigned FpCallId,
                               ArrayRef<Value *> Args,
                               Type *RetTy) {
    Type *I64Ty = Type::getInt64Ty(Ctx);
    // 构造函数指针类型：(RetTy)(ArgTys...)。ArgTys 用各参数自身的类型。
    SmallVector<Type *, 4> ArgTys;
    for (Value *A : Args)
        ArgTys.push_back(A->getType());
    FunctionType *FTy = FunctionType::get(RetTy, ArgTys, false);

    // 函数指针 = inttoptr (i64 FpCallId)。
    Value *FnPtr = B.CreateIntToPtr(ConstantInt::get(I64Ty, FpCallId),
                                    PointerType::get(FTy, 0));
    return B.CreateCall(FTy, FnPtr, Args);
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
                case Instruction::FAdd: callId = sfx[0]=='d' ? BPF_CALL_FP_ADD_D : BPF_CALL_FP_ADD_F; break;
                case Instruction::FSub: callId = sfx[0]=='d' ? BPF_CALL_FP_SUB_D : BPF_CALL_FP_SUB_F; break;
                case Instruction::FMul: callId = sfx[0]=='d' ? BPF_CALL_FP_MUL_D : BPF_CALL_FP_MUL_F; break;
                case Instruction::FDiv: callId = sfx[0]=='d' ? BPF_CALL_FP_DIV_D : BPF_CALL_FP_DIV_F; break;
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

                unsigned callId = sfx[0]=='d' ? BPF_CALL_FP_NEG_D : BPF_CALL_FP_NEG_F;
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
                        if (Dst->isIntegerTy(32))      callId = isDouble ? BPF_CALL_FP_D2SI : BPF_CALL_FP_F2SI;
                        else if (Dst->isIntegerTy(64)) callId = isDouble ? BPF_CALL_FP_D2DI : BPF_CALL_FP_F2DI;
                        else continue;
                    } else {
                        if (Dst->isIntegerTy(32))      callId = isDouble ? BPF_CALL_FP_D2USI : BPF_CALL_FP_F2USI;
                        else if (Dst->isIntegerTy(64)) callId = isDouble ? BPF_CALL_FP_D2UDI : BPF_CALL_FP_F2UDI;
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
                        if (Src->isIntegerTy(32))      callId = isDouble ? BPF_CALL_FP_SI2D : BPF_CALL_FP_SI2F;
                        else if (Src->isIntegerTy(64)) callId = isDouble ? BPF_CALL_FP_DI2D : BPF_CALL_FP_DI2F;
                        else continue;
                    } else {
                        if (Src->isIntegerTy(32))      callId = isDouble ? BPF_CALL_FP_USI2D : BPF_CALL_FP_USI2F;
                        else if (Src->isIntegerTy(64)) callId = isDouble ? BPF_CALL_FP_UDI2D : BPF_CALL_FP_UDI2F;
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
                    Value *Call = emitDirectFpCall(B, Ctx, BPF_CALL_FP_TRUNC, {CI->getOperand(0)}, Dst);
                    CI->replaceAllUsesWith(Call);
                    ToErase.push_back(CI);
                    Changed = true;
                    continue;
                }

                if (Op == Instruction::FPExt) {
                    // float -> double
                    if (!Src->isFloatTy() || !Dst->isDoubleTy()) continue;
                    Value *Call = emitDirectFpCall(B, Ctx, BPF_CALL_FP_EXTEND, {CI->getOperand(0)}, Dst);
                    CI->replaceAllUsesWith(Call);
                    ToErase.push_back(CI);
                    Changed = true;
                    continue;
                }
            }

            // ---- 浮点 intrinsic：fmuladd / fma ----
            // clang 常把 `a*b+c` 收缩成 @llvm.fmuladd / @llvm.fma，必须展开后软化。
            // 这里直接发两条 BPF_CALL_FP_*（mul + add），避免新生成的 fp 指令被漏掉。
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
                    unsigned mulId = isDouble ? BPF_CALL_FP_MUL_D : BPF_CALL_FP_MUL_F;
                    unsigned addId = isDouble ? BPF_CALL_FP_ADD_D : BPF_CALL_FP_ADD_F;
                    Value *Mul = emitDirectFpCall(B, Ctx, mulId, {A, B_}, Ty);
                    Value *Add = emitDirectFpCall(B, Ctx, addId, {Mul, C}, Ty);
                    II->replaceAllUsesWith(Add);
                    ToErase.push_back(II);
                    Changed = true;
                    continue;
                }
                // sqrt：VM 侧有 BPF_CALL_FP_SQRT_D/F，直接发。
                if (II->getIntrinsicID() == Intrinsic::sqrt) {
                    const char *sfx = suffix(Ty);
                    if (!sfx) continue;
                    unsigned callId = (sfx[0]=='d') ? BPF_CALL_FP_SQRT_D : BPF_CALL_FP_SQRT_F;
                    Value *Call = emitDirectFpCall(B, Ctx, callId, {II->getArgOperand(0)}, Ty);
                    II->replaceAllUsesWith(Call);
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
                unsigned cmpId   = is_d ? BPF_CALL_FP_CMP_D   : BPF_CALL_FP_CMP_F;
                unsigned unordId = is_d ? BPF_CALL_FP_UNORD_D : BPF_CALL_FP_UNORD_F;
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
