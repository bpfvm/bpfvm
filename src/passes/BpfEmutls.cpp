//===- BpfEmutls.cpp - emutls via address_space(256) ---------------------===//
//
// BPF 后端不支持 thread_local（Sema 直接拒，后端 ISel 遇 GlobalTLSAddress 会
// crash）。本 pass 提供一条绕过路径：用户用 `__attribute__((address_space(256)))`
// 标记"每线程一份"的变量（通常经 `__mythread` 宏），本 pass 在 IR 层把对
// addrspace(256) 全局的访问改写成对 FP 通道虚拟指令的调用 + 对返回的普通指针
// 的访问。
//
// 编码链路（复用 BpfSoftFp 的 FP 虚拟指令通道，linker/JIT 零额外改动）：
//   1. 用户：`__mythread int x = 0;`（宏展开成 addrspace(256) 全局）
//   2. clang：产出 `@x = addrspace(256) global i32 0` + `load/store/GEP ptr addrspace(256) @x`
//   3. 本 pass：为 x 生成控制块 `@__emutls_v.x = {size, align, index, value*}`（+ 非
//      零初始化时另生成模板 `@__emutls_t.x`），把所有对 addrspace(256) 全局的访问
//      改写成：
//        %p = call i64 @__bpf_fp_<EMUTLS_ID>(i64 ptrtoint(@__emutls_v.x))
//        %q = inttoptr %p to ptr
//        load/store/GEP ... ptr %q
//      其中 `__bpf_fp_<EMUTLS_ID>` 是 extern + section ".ksyms"（与 FP 同手法）。
//   4. clang 后端：emit `call -1`（src_reg=1）+ R_BPF_64_32 重定位。
//   5. bpfvm-ld：识别 `__bpf_fp_` 前缀（is_fp_ksym，与 FP 共用），改写 call 的
//      src_reg=2 + imm=<EMUTLS_ID>。无额外 linker 改动。
//   6. VM/JIT：src_reg==2 走 do_softfp（FP 通道），switch 命中 BPF_FP_EMUTLS_GET_ADDR
//      时从 r1 取控制块指针，分配/查每线程副本，返回地址写 r0。JIT 对该 ID 自动
//      走 slow path（emit_call_softfp_slow → helper_do_softfp）。
//
// 处理的 IR 形态：直接 load/store、GEP（含 -O0/-O1 下嵌在 load/store 指针 operand
// 里的 ConstantExpr 形式 GEP/bitcast）。不支持：取地址 &var（addrspace 不兼容，
// 编译期报错）、跨 TU 的 extern TLS 变量（控制块用 InternalLinkage）。
//
// 用法：clang -target bpf -fpass-plugin=libBpfEmutls.so ...
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/CFG.h" // instructions()
#include "llvm/IR/Type.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

// BPF_FP_EMUTLS_GET_ADDR 定义（复用 FP 通道）。
#include "include/bpf_call.h"

using namespace llvm;

namespace {

// clang 用 address_space(256) 标记的 emutls 变量的地址空间编号。
constexpr unsigned kEmutlsAddrspace = 256;

// emutls 控制块布局（与 compiler-rt/lib/builtins/emutls.c 一致）：
//   { i64 size, i64 align, i64 index, ptr value }
// index 初值 0（运行时懒分配）；value 为 null（零初始化）或指向初始化模板。
StructType *getEmutlsControlType(LLVMContext &Ctx) {
    Type *I64 = Type::getInt64Ty(Ctx);
    Type *Ptr = PointerType::get(Ctx, 0);
    return StructType::get(Ctx, {I64, I64, I64, Ptr});
}

// 获取或声明 extern `ptr @__bpf_fp_<ID>(ptr)`，section ".ksyms"。
// 复用 FP 通道（src_reg=2）：符号名形如 __bpf_fp_<ID>，linker 的 is_fp_ksym
// 自动识别尾部数字并改写 src_reg=2 + imm=<ID>，零额外 linker 改动。
// 入参用 i64 传递（与 FP ABI 一致：r1），结果也是 i64（r0）——指针当 i64 位模式。
FunctionCallee declareEmutlsGetAddress(Module &M) {
    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);
    // (i64) -> i64：指针参数/返回值按位模式当 i64 传（与 FP ABI 一致）。
    FunctionType *FTy = FunctionType::get(I64, {I64}, false);
    std::string Name = "__bpf_fp_" + std::to_string(BPF_FP_EMUTLS_GET_ADDR);
    FunctionCallee FC = M.getOrInsertFunction(Name, FTy);
    if (auto *F = dyn_cast<Function>(FC.getCallee())) {
        F->setLinkage(GlobalValue::ExternalLinkage);
        if (!F->hasSection())
            F->setSection(".ksyms");
    }
    return FC;
}

// 为一个 addrspace(256) 全局变量生成控制块 `@__emutls_v.<name>`（放在默认
// addrspace(0) 的 .data）。如果有非零 initializer，另生成模板全局
// `@__emutls_t.<name>` 并让控制块的 value 字段指向它。
//
// 返回控制块全局（addrspace(0)），调用方负责删除原 addrspace(256) 全局。
GlobalVariable *buildEmutlsControl(Module &M, GlobalVariable *GV) {
    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);
    Type *Ptr = PointerType::get(Ctx, 0);

    // 原 GV 的元素类型（addrspace(256) 全局）。
    Type *ElemTy = GV->getValueType();
    const uint64_t Size = M.getDataLayout().getTypeAllocSize(ElemTy);
    const uint64_t Align = M.getDataLayout().getPrefTypeAlign(ElemTy).value();

    // value 指针：零初始化 → null；非零 → 新建模板全局 __emutls_t.<name>。
    Constant *ValueInit = ConstantPointerNull::get(cast<PointerType>(Ptr));
    Constant *GVInit = GV->getInitializer();
    bool isZeroInit = GVInit->isNullValue();
    if (!isZeroInit) {
        // 拷贝 initializer 到一个新的 addrspace(0) 模板全局。
        std::string TmplName = "__emutls_t." + GV->getName().str();
        auto *Tmpl = new GlobalVariable(
            M, ElemTy, /*isConstant*/ true, GlobalValue::InternalLinkage,
            GVInit, TmplName, nullptr, GlobalValue::NotThreadLocal, 0);
        Tmpl->setAlignment(M.getDataLayout().getPrefTypeAlign(ElemTy));
        ValueInit = ConstantExpr::getBitCast(Tmpl, Ptr);
    }

    // 控制块 initializer：{ size, align, index=0, value }
    Constant *CtrlInit = ConstantStruct::get(
        getEmutlsControlType(Ctx),
        {ConstantInt::get(I64, Size), ConstantInt::get(I64, Align),
         ConstantInt::get(I64, 0), ValueInit});

    std::string CtrlName = "__emutls_v." + GV->getName().str();
    auto *Ctrl = new GlobalVariable(
        M, getEmutlsControlType(Ctx), /*isConstant*/ false,
        GlobalValue::InternalLinkage, CtrlInit, CtrlName, nullptr,
        GlobalValue::NotThreadLocal, 0);
    Ctrl->setAlignment(llvm::Align(8));
    return Ctrl;
}

// ModulePass：遍历所有 addrspace(256) 全局，建控制块；改写所有对它们的
// load/store（直接访问形式）为 __emutls_get_address 调用 + 普通指针解引用。
struct BpfEmutlsPass : public PassInfoMixin<BpfEmutlsPass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        SmallVector<GlobalVariable *, 8> EmutlsGlobals;
        for (GlobalVariable &GV : M.globals()) {
            if (GV.getType()->getAddressSpace() == kEmutlsAddrspace &&
                !GV.isDeclaration())
                EmutlsGlobals.push_back(&GV);
        }
        if (EmutlsGlobals.empty())
            return PreservedAnalyses::all();

        FunctionCallee GetAddr = declareEmutlsGetAddress(M);

        // 为每个 emutls 全局建控制块，记录映射。
        DenseMap<GlobalVariable *, GlobalVariable *> CtrlOf;
        for (GlobalVariable *GV : EmutlsGlobals)
            CtrlOf[GV] = buildEmutlsControl(M, GV);

        // 改写所有函数内对 emutls 全局的直接 load/store。
        bool Changed = false;
        for (Function &F : M) {
            if (F.isDeclaration())
                continue;
            Changed |= rewriteFunction(F, CtrlOf, GetAddr);
        }

        // 删除原 addrspace(256) 全局（数据已迁到控制块/模板）。
        for (GlobalVariable *GV : EmutlsGlobals) {
            // 改写过程中，引用 GV 的 ConstantExpr（如 gep(@arr,...)）在被指令
            // 替换后，其本身对 GV 的 use 仍挂在 user 列表里。这些 ConstantExpr 无
            // 任何实际使用者，可安全清除。
            GV->removeDeadConstantUsers();
            if (GV->use_empty())
                GV->eraseFromParent();
            else
                errs() << "BpfEmutls: WARNING: " << GV->getName()
                       << " still has " << GV->getNumUses()
                       << " uses after rewrite (unsupported form)\n";
        }

        return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

  private:
    // 把一个 emutls 全局在指令 I 处的使用替换成 __emutls_get_address 调用返回的
    // 普通 ptr。返回插入的指针 Value（addrspace 0）。
    Value *materializeAddress(Instruction *I, GlobalVariable *Ctrl,
                              FunctionCallee GetAddr) {
        IRBuilder<> B(I);
        Type *I64 = Type::getInt64Ty(I->getContext());
        Type *Ptr0 = PointerType::get(I->getContext(), 0);
        Value *CtrlI64 = B.CreatePtrToInt(Ctrl, I64);
        Value *AddrI64 = B.CreateCall(GetAddr, {CtrlI64});
        return B.CreateIntToPtr(AddrI64, Ptr0);
    }

    // 判断一个 Value（含 ConstantExpr）是否涉及某个 emutls 全局。
    // ConstantExpr 如 `gep(256 @arr, ...)` 内部会引用 GV，需递归检查。
    static GlobalVariable *findEmutlsGlobal(const Value *V,
                              const DenseMap<GlobalVariable *, GlobalVariable *> &CtrlOf) {
        V = V->stripPointerCasts();
        if (auto *GV = const_cast<GlobalVariable *>(dyn_cast<GlobalVariable>(V)))
            return CtrlOf.count(GV) ? GV : nullptr;
        // ConstantExpr：递归 operand 查找。
        if (auto *CE = dyn_cast<ConstantExpr>(V)) {
            for (const Use &U : CE->operands()) {
                if (auto *GV = findEmutlsGlobal(U.get(), CtrlOf))
                    return GV;
            }
        }
        return nullptr;
    }

    bool rewriteFunction(Function &F,
                         const DenseMap<GlobalVariable *, GlobalVariable *> &CtrlOf,
                         FunctionCallee GetAddr) {
        bool Changed = false;

        // 第一阶段：把所有以 ConstantExpr 形式引用 emutls 全局的 operand 展开成
        // 真实指令（CL在被使用处插一条 Instruction）。这样后续阶段只需处理指令形式。
        // clang -O0/-O1 对 `arr[i]`、`&s->field` 等会生成 ConstantExpr 形式的 GEP/
        // bitcast 嵌进 load/store 的指针 operand，无法直接替换。
        SmallVector<std::pair<Use *, GlobalVariable *>, 32> CEWorklist;
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                for (Use &U : I.operands()) {
                    if (!isa<ConstantExpr>(U.get())) continue;
                    if (auto *GV = findEmutlsGlobal(U.get(), CtrlOf))
                        CEWorklist.push_back({&U, GV});
                }
            }
        }
        for (auto &[U, GV] : CEWorklist) {
            auto *CE = cast<ConstantExpr>(U->get());
            auto *I = cast<Instruction>(U->getUser());
            // 把 ConstantExpr 在 I 之前展开成 Instruction。
            Instruction *Expanded = CE->getAsInstruction();
            Expanded->insertBefore(I);
            U->set(Expanded);
            Changed = true;
        }

        // 第二阶段：处理所有"以 emutls 全局为源指针"的 GetElementPtrInst（含上一
        // 阶段从 ConstantExpr 展开出来的）。GEP 的 result type 带 addrspace(256)，
        // 不能只换 operand——必须整体重建一个普通 addrspace(0) 的 GEP，再 RAUW。
        SmallVector<GetElementPtrInst *, 16> GEPs;
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                auto *GEP = dyn_cast<GetElementPtrInst>(&I);
                if (!GEP) continue;
                auto *GV = findEmutlsGlobal(GEP->getPointerOperand(), CtrlOf);
                if (GV)
                    GEPs.push_back(GEP);
            }
        }
        for (GetElementPtrInst *GEP : GEPs) {
            auto *GV = findEmutlsGlobal(GEP->getPointerOperand(), CtrlOf);
            GlobalVariable *Ctrl = CtrlOf.at(GV);
            // GEP 的 pointer operand 可能是 GV 本身，也可能是 stripPointerCasts 后
            // 是 GV 的 bitcast。先在 GEP 处 materialize 拿到普通 ptr 基地址。
            Value *Base = materializeAddress(GEP, Ctrl, GetAddr);
            IRBuilder<> B(GEP);
            // 若原指针经 bitcast，重建 bitcast(Base)。
            Value *OrigPtr = GEP->getPointerOperand();
            if (OrigPtr != GV && OrigPtr->stripPointerCasts() == GV) {
                if (auto *BC = dyn_cast<BitCastOperator>(OrigPtr))
                    Base = B.CreateBitCast(Base, BC->getType());
            }
            SmallVector<Value *, 4> Idxs(GEP->indices().begin(), GEP->indices().end());
            Value *NewGEP = B.CreateGEP(GEP->getSourceElementType(), Base, Idxs,
                                         GEP->getName() + ".emutls", GEP->isInBounds());
            GEP->replaceAllUsesWith(NewGEP);
            GEP->eraseFromParent();
            Changed = true;
        }

        // 第三阶段：剩余所有直接以 emutls 全局（或其 bitcast 包裹）为 operand 的
        // 指令（load/store/icmp 等）。
        SmallVector<std::pair<Instruction *, GlobalVariable *>, 16> Worklist;
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                for (Value *Op : I.operands()) {
                    if (auto *GV = findEmutlsGlobal(Op, CtrlOf))
                        Worklist.push_back({&I, GV});
                }
            }
        }
        for (auto &[I, GV] : Worklist) {
            GlobalVariable *Ctrl = CtrlOf.at(GV);
            Value *Ptr = materializeAddress(I, Ctrl, GetAddr);
            for (Use &U : I->operands()) {
                Value *V = U.get();
                if (V == GV) {
                    U.set(Ptr);
                } else if (V->stripPointerCasts() == GV) {
                    IRBuilder<> B(I);
                    if (auto *BC = dyn_cast<BitCastOperator>(V))
                        U.set(B.CreateBitCast(Ptr, BC->getType()));
                    else
                        U.set(Ptr);
                }
            }
            Changed = true;
        }
        return Changed;
    }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "BpfEmutls", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                // 必须早跑：在常量折叠/GlobalOpt 把 addrspace(256) 全局当成
                // 可折叠常量之前。PipelineStartEP 全档位（-O0/-O1+ 都跑）。
                auto addPass = [](ModulePassManager &MPM) {
                    MPM.addPass(BpfEmutlsPass());
                };
                PB.registerPipelineStartEPCallback(
                    [addPass](ModulePassManager &MPM, OptimizationLevel) {
                        addPass(MPM);
                    });
            }};
}
