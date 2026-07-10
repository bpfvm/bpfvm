//===- BpfLibcallLower.cpp - intrinsic → libcall 改写 --------------------===//
//
// BPF 后端在 ISel 阶段拒绝一批 LLVM intrinsic，报 "A call to built-in
// function 'memcpy' is not supported" 等。-fno-builtin 只阻止"把 libc 调用
// 变 builtin"，不阻止"把结构体拷贝/数学优化变 intrinsic"——C++ 的隐式拷贝
// （构造/赋值、vector realloc、string 拼接）大量生成 memcpy/memmove/memset
// intrinsic；优化器也会把 floor/ceil 等库调用折叠回同名 intrinsic。这些都会被
// BPF 后端 ISel 拒绝，是 STL/浮点可用的主要阻塞点之一。
//
// 本 pass 在 IR 层把这些 intrinsic 替换成对 musl 提供的普通函数的 call（BPF
// 后端正常选 call 指令）。统一处理两类"后端拒收、但 libc/libm 有纯 C 实现"的
// intrinsic：
//   内存：@llvm.memcpy/memmove/memset → call memcpy/memmove/memset
//   数学：@llvm.floor/ceil/trunc/round → call floor/ceil/trunc/round（+f）
//         （musl src/math/*.c 纯 C 实现，后端能编译；源码直接调 floor() 本就是
//          合法普通 call，后端能选 call，无需本 pass 介入
//   控制：@llvm.trap → call abort（libc++ new.cpp 等会调 abort() 被 builtin 化）
//
// 时机：registerOptimizerLastEPCallback（-O1+）/ registerPipelineStartEPCallback
// （-O0 兜底）。必须在 CodeGen 之前（ISel 才会拒绝 intrinsic），但尽量晚跑让
// 优化器有机会把小尺寸 intrinsic 内联消除（避免不必要的 call）。对动态长度
// intrinsic 优化器无法消除，本 pass 兜底改写。
//
// 用法：clang -target bpf -fpass-plugin=libBpfLibcallLower.so ...
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

namespace {

// 把单参数数学 intrinsic（floor/ceil/trunc/round）lower 成对 musl libm 函数的
// 普通 call。单精度加 'f' 后缀（musl 约定：floorf/ceilf/...）。参数类型取返回
// 类型——这四个函数都是 (T)->T 单参，Args 全部同 Ty。
static Value *emitLibmCall(IRBuilder<> &B, const char *baseName, Type *Ty,
                           ArrayRef<Value *> Args) {
    std::string Name = Ty->isFloatTy() ? std::string(baseName) + "f" : baseName;
    Module &M = *B.GetInsertBlock()->getModule();
    FunctionType *FTy = FunctionType::get(Ty, SmallVector<Type *, 2>(Args.size(), Ty), false);
    FunctionCallee FC = M.getOrInsertFunction(Name, FTy);
    return B.CreateCall(FC, Args);
}

struct BpfLibcallLowerPass : public PassInfoMixin<BpfLibcallLowerPass> {
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        if (F.isDeclaration())
            return PreservedAnalyses::all();

        Module &M = *F.getParent();
        LLVMContext &Ctx = M.getContext();
        Type *I64 = Type::getInt64Ty(Ctx);
        Type *I32 = Type::getInt32Ty(Ctx);
        Type *Ptr = PointerType::get(Ctx, 0);

        // 获取或声明对应 libc 函数（musl 提供）。memcpy/memmove/memset 按标准语义：
        //   void *memcpy(void *, const void *, size_t)
        //   void *memset(void *, int, size_t)
        auto get_callee = [&](const char *name, FunctionType *fty) -> FunctionCallee {
            return M.getOrInsertFunction(name, fty);
        };
        FunctionType *MemCpyTy = FunctionType::get(Ptr, {Ptr, Ptr, I64}, false);
        FunctionType *MemSetTy = FunctionType::get(Ptr, {Ptr, I32, I64}, false);
        FunctionType *AbortTy = FunctionType::get(Type::getVoidTy(Ctx), {}, false);

        bool Changed = false;
        SmallVector<IntrinsicInst *, 16> ToRewrite;
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                auto *II = dyn_cast<IntrinsicInst>(&I);
                if (!II) continue;
                switch (II->getIntrinsicID()) {
                case Intrinsic::memcpy:
                case Intrinsic::memmove:
                case Intrinsic::memset:
                case Intrinsic::trap:
                case Intrinsic::floor:
                case Intrinsic::ceil:
                case Intrinsic::trunc:
                case Intrinsic::round:
                    ToRewrite.push_back(II);
                    break;
                default:
                    break;
                }
            }
        }

        for (IntrinsicInst *II : ToRewrite) {
            IRBuilder<> B(II);
            Intrinsic::ID ID = II->getIntrinsicID();

            if (ID == Intrinsic::memcpy || ID == Intrinsic::memmove) {
                // @llvm.memcpy/memmove(dst ptr, src ptr, len i64, isvolatile i1)
                Value *Dst = II->getArgOperand(0);
                Value *Src = II->getArgOperand(1);
                Value *Len = II->getArgOperand(2);
                const char *name = (ID == Intrinsic::memcpy) ? "memcpy" : "memmove";
                FunctionCallee FC = get_callee(name, MemCpyTy);
                // 确保参数类型匹配（指针 addrspace、整数宽度）。
                if (Dst->getType() != Ptr) Dst = B.CreatePointerCast(Dst, Ptr);
                if (Src->getType() != Ptr) Src = B.CreatePointerCast(Src, Ptr);
                if (Len->getType() != I64) Len = B.CreateZExtOrTrunc(Len, I64);
                B.CreateCall(FC, {Dst, Src, Len});
            } else if (ID == Intrinsic::memset) {
                // @llvm.memset(dst ptr, val i8, len i64, isvolatile i1)
                Value *Dst = II->getArgOperand(0);
                Value *Val = II->getArgOperand(1);
                Value *Len = II->getArgOperand(2);
                FunctionCallee FC = get_callee("memset", MemSetTy);
                if (Dst->getType() != Ptr) Dst = B.CreatePointerCast(Dst, Ptr);
                // memset 的 val 是 int，从 i8 zext 到 i32。
                if (Val->getType() != I32) Val = B.CreateZExtOrTrunc(Val, I32);
                if (Len->getType() != I64) Len = B.CreateZExtOrTrunc(Len, I64);
                B.CreateCall(FC, {Dst, Val, Len});
            } else if (ID == Intrinsic::trap) {
                // @llvm.trap → call abort()（libc++ new.cpp 等会调 abort() 被 builtin 化）。
                FunctionCallee FC = get_callee("abort", AbortTy);
                B.CreateCall(FC);
            } else {
                // floor/ceil/trunc/round：单参 (T)->T 数学 intrinsic → musl libm call。
                // 与上面 void 返回的 memcpy/memset/trap 不同，这些有返回值使用者，
                // 必须 replaceAllUsesWith 再删除。
                const char *name = nullptr;
                switch (ID) {
                case Intrinsic::floor: name = "floor"; break;
                case Intrinsic::ceil:  name = "ceil";  break;
                case Intrinsic::trunc: name = "trunc"; break;
                case Intrinsic::round: name = "round"; break;
                default: break;
                }
                Value *Call = emitLibmCall(B, name, II->getType(), {II->getArgOperand(0)});
                II->replaceAllUsesWith(Call);
            }
            II->eraseFromParent();
            Changed = true;
        }

        return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "BpfLibcallLower", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                // 晚跑（optimizer 末尾）：让优化器先消除可内联的小尺寸 intrinsic，
                // 只改写剩下来的（动态长度/大尺寸/数学 intrinsic）。
                auto addPass = [](ModulePassManager &MPM) {
                    FunctionPassManager FPM;
                    FPM.addPass(BpfLibcallLowerPass());
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
                // -O0 兜底：直接在管道起始跑。
                PB.registerPipelineStartEPCallback(
                    [addPass](ModulePassManager &MPM, OptimizationLevel OL) {
                        if (OL == OptimizationLevel::O0)
                            addPass(MPM);
                    });
            }};
}
