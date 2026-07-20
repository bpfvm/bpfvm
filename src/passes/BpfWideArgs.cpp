//===- BpfWideArgs.cpp - BPF 参数/变参/struct 返回/VLA/alloca 综合改写 -----===//
//
// 本插件在一个 .so 里注册两个独立 pass，挂在各自正确的 pipeline EP：
//
// A. BpfWideArgsPass（ModulePass，PipelineStartEPCallback，所有 -O 都触发）
//    解决 BPF 后端调用约定的三类限制：
//
// 1. >5 参数：BPF 后端拒绝参数个数 >5 的函数（"stack arguments are not
//    supported"）。本 pass 把第 6 个及以后的参数打包成一个结构体，通过一个
//    结构体指针（占第 5 个寄存器位）传递。
//      int  f(int a,b,c,d,e, int g, int h);
//           ↓ 改写为
//      int  f(int a,b,c,d,e, struct{ int g; int h; } *__wide);
//
// 2. 返回 struct：BPF 后端拒绝 sret 属性（"aggregate returns are not
//    supported"）。本 pass 剥掉 sret 属性（LLVM 已把 struct 返回降级为输出
//    指针，语义不变）。
//
// 3. 变参函数（...）：BPF 后端拒绝任何 isVarArg 的函数（"variadic functions
//    are not supported"）。本 pass 把变参函数改写成定参 + 末尾一个 ptr
//    __va_base，并 lower 体内的 va_start/va_arg/va_end/va_copy intrinsic。
//    采用 clang 原生 void* 裸指针 ABI（BPF 的 VoidPtrBuiltinVaList）。
//      int  f(int n, ...) { va_list ap; va_start(ap,n); ... va_arg(ap,int) ... }
//           ↓ 改写为
//      int  f(int n, ptr __va_base) { ... load + 指针推进 ... }
//    调用点：在栈上 alloca 一段内存，按变参实参布局填值，传首地址。
//
// 4. syscall 形式的 6 参调用（call <imm>，src_reg=0， callee =
//    inttoptr(ConstantInt)）：BPF call 指令的 syscall 形式最多 6 参。前 5 个
//    走 r1..r5，第 6 个【特殊地】放在 r0 —— BPF 的 r0 一般是返回值，但 syscall
//    是宿主拦截的瞬间指令，调用前 r0 可作输入，调用后即被返回覆盖，无冲突。
//    pass 通过一条 side-effect 内联 asm 把第 6 参绑定到 r0（clobber r1..r9
//    强制 input 选 r0，并让后端自动 spill/reload r1..r5），随后重建 5 参 call。
//    普通 >5 参函数不受影响，仍走 packed struct 路径。syscall 实参超 6 报错。
//
// B. BpfVlaPass（FunctionPass，OptimizerLastEPCallback + -O0 兜底）
//    把 C 的 VLA（int buf[n]）/ __builtin_alloca / 非入口块固定 alloca + 配套
//    的 llvm.stacksave / llvm.stackrestore intrinsic 改写成对 BPF_SYS_ALLOCA
//    syscall 的调用，由 VM 在栈帧上分配（frame_base[0] 低 32 位记录累计
//    alloca 量，详见 insn.h）。必须晚跑（在 SROA/instcombine 之后），让固定
//    大小 alloca 先被消除，只改写"漏网"的动态/非入口块 alloca；与 A 无数据
//    依赖（A 只碰 CallBase/sret/va intrinsic，不碰 alloca/stacksave/restore）。
//
// 用法：clang -target bpf -fpass-plugin=libBpfWideArgs.so ...
//
//===----------------------------------------------------------------------===*/

#include "include/bpf_call.h"   // BPF_CALL_ALLOCA（VLA 路径用）

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

// BPF 后端限制是 5 个参数，所以 >5 就需要打包。
// 第 5 个位置用来放结构体指针，前 4 个仍是寄存器参数。
constexpr unsigned KEEP_REGS = 4;          // 保留为寄存器参数的个数
constexpr unsigned BPF_ARG_LIMIT = 5;      // BPF 后端的硬上限

// 通用排除条件：对所有改写路径都适用。
// 排除 llvm.* / __clang_ 等内部符号、intrinsic。
static bool isInternalOrIntrinsic(Function &F) {
    if (F.getName().starts_with("llvm."))
        return true;
    if (F.getIntrinsicID() != Intrinsic::not_intrinsic)
        return true;
    return false;
}

// 判断 callee（CallBase 的 called operand）是否是 syscall 形式：
//   inttoptr (ConstantInt <id>) to ptr
// BPF 后端把这种 callee lower 成 `call <imm>`（src_reg=0），即一条 syscall 指令。
// 关键：这种 call 最多 6 参，前 5 个走 r1..r5，第 6 个用 r0 当输入（见文件头注释
// 第 4 条）。本 pass 对这种 call site 走专门的 syscall 路径，不走 packed struct。
static bool isSyscallCallee(Value *Callee) {
    // BPF syscall 形式 callee = inttoptr <id> to ptr。两种出现形态：
    //   1) 常量折叠后：callee 是 ConstantExpr(IntToPtr, ConstantInt) —— 已 constprop
    //      过的常见形态（如 musl __bpf_syscall6 直接调用、测试 reduced_syscall6）。
    //   2) 内联后未 constprop：callee 是 IntToPtr 指令（Instruction），其操作数是
    //      sext/zext 自函数参数 —— musl `__syscall6(n, ...)` 内联进 caller 后的形态
    //      （n 此时是 Argument 而非 ConstantInt；instcombine 还没把 call site 的常量
    //      实参 constprop 进内联体）。pass 跑在 PipelineStartEP 早于 instcombine。
    //      后续 instcombine 会把操作数折叠成常量，BPF 后端再 lower 成 call <imm>。
    //
    // 关键判据：callee 形态是 IntToPtr（无论常量形式还是指令形式）。BPF 用户态代码
    // 用 inttoptr 当函数指针调用的只有 syscall 形式这一种，不会误判。
    if (auto *CE = dyn_cast<ConstantExpr>(Callee))
        return CE->getOpcode() == Instruction::IntToPtr;
    if (auto *I = dyn_cast<Instruction>(Callee))
        return I->getOpcode() == Instruction::IntToPtr;
    return false;
}

// 判断一个函数是否是变参函数（需要 varargs 改写路径）。
// 包含：有定义的变参函数、被调用的变参声明（prototype）。
// 排除：无定义且无人调用、内部符号/intrinsic。
static bool isVarArgFunction(Function &F) {
    if (F.isDeclaration() && F.use_empty())
        return false;                      // 无定义又没人调用，不用管
    if (isInternalOrIntrinsic(F))
        return false;
    return F.isVarArg();
}

// 判断一个函数是否需要改写（>5 参数路径）：
//  - 参数个数 > 5
//  - 不是变参（变参走 isVarArgFunction 单独路径）
//  - 不是声明（要么有定义体，要么是用户声明的 prototype——但只有有 call 点才有意义）
// 排除 llvm.* / __clang_ 等内部符号。
bool needsRewrite(Function &F) {
    if (F.isDeclaration() && F.use_empty())
        return false;                      // 无定义又没人调用，不用管
    if (F.isVarArg())
        return false;                      // 变参走 isVarArgFunction 路径
    if (isInternalOrIntrinsic(F))
        return false;
    return F.arg_size() > BPF_ARG_LIMIT;
}

// 构造打包结构体类型：把第 KEEP_REGS（即第5个，索引4）之后的参数类型依次放进去。
// 注意：原本第 5 个参数（索引 4）也要进结构体，因为第 5 个寄存器位留给指针本身。
//
// 用 **packed** 结构体：字段偏移 = 各字段 allocSize 之和，无对齐填充。这样 caller 侧
// （用 i8* + 字节偏移 store 共享缓冲区）与 callee 侧（用结构体 GEP+Load）的布局自洽。
StructType *buildPackType(Function &F) {
    SmallVector<Type *, 8> elems;
    for (auto it = F.arg_begin() + KEEP_REGS; it != F.arg_end(); ++it) {
        elems.push_back(it->getType());
    }
    // 用函数名命名，便于调试 & 跨模块一致；packed 保证字段偏移 = allocSize 之和
    return StructType::create(F.getContext(), elems,
                              ("__bpf_pack_" + F.getName()).str(),
                              true /*packed*/);
}

// 改写函数：构造新签名，克隆函数体，把对原第 5+ 参数的引用替换为从结构体指针 load。
// 返回新的 Function*（旧的会被删掉/清空）。
Function *rewriteFunction(Function &F, StructType *PackTy) {
    Module &M = *F.getParent();

    // 1. 构造新参数类型表：前 KEEP_REGS 个原样 + 1 个 PackTy*
    SmallVector<Type *, 8> newArgTys;
    for (unsigned i = 0; i < KEEP_REGS && i < F.arg_size(); ++i)
        newArgTys.push_back(F.getFunctionType()->getParamType(i));
    newArgTys.push_back(PointerType::getUnqual(PackTy));

    FunctionType *newFTy = FunctionType::get(F.getReturnType(), newArgTys, false);

    // 2. 创建新函数（同 module 同名会冲突，先用临时名，最后再换）
    Function *NewF = Function::Create(
        newFTy, F.getLinkage(), F.getAddressSpace(),
        "__bpf_wide_tmp_" + F.getName(), &M);

    // 复制关键属性（noinline/norecurse 等对 BPF 重要，但 visibility/attrs 整体搬）
    NewF->copyAttributesFrom(&F);
    NewF->setVisibility(F.getVisibility());
    NewF->setComdat(F.getComdat());
    NewF->setSection(F.getSection());
    NewF->setDSOLocal(F.isDSOLocal());

    // 声明（prototype，无定义）：只换签名即可，没有函数体可搬/可改。它的真正定义
    // 在另一个 TU（那里会被本 pass 同样改写，签名一致）。调用点改写在第二阶段处理。
    // 这一支路关键：BPF 后端对 >5 参的「调用」也会拒绝，所以即便 callee 是声明，
    // 调用点也必须改写；而调用点改写要求 callee 签名匹配新 ABI，故声明也必须重签。
    if (F.isDeclaration()) {
        NewF->takeName(&F);
        F.dropAllReferences();
        return NewF;
    }

    // 3. 把旧函数体整体 move 过来：把所有 BasicBlock 从 F 搬到 NewF
    NewF->splice(NewF->end(), &F);
    NewF->takeName(&F);  // 拿回原名（此时旧 F 已被改名）

    // 4. 建立"旧第5+参数 → 从结构体 load 的新值"的映射，并用 IRBuilder 插入 load。
    //    插入点：函数入口块第一个非 phi、非 alloca 指令前（保证支配所有 use）。
    BasicBlock &Entry = NewF->front();
    Instruction *InsertPt = &Entry.front();
    // 跳过前导 phi / alloca；getNextNode 可能为 null（块全是 phi/alloca 且无终止符，
    // 罕见但可能），需要判空，否则 isa<PHINode>(nullptr) 会触发断言崩溃。
    while (InsertPt && (isa<PHINode>(InsertPt) || isa<AllocaInst>(InsertPt)))
        InsertPt = InsertPt->getNextNode();
    if (!InsertPt) {
        // 兜底：直接插到入口块末尾（终止符之前）。
        InsertPt = Entry.getTerminator();
    }

    // 第 5 个新参数（索引 KEEP_REGS）= PackTy*
    Value *PackPtr = NewF->getArg(KEEP_REGS);

    std::vector<std::pair<Argument *, Value *>> replacements;
    unsigned oldIdx = 0;
    unsigned packIdx = 0;
    for (Argument &OldArg : F.args()) {
        if (oldIdx < KEEP_REGS) {
            // 前 4 个：映射到新函数对应参数
            replacements.emplace_back(&OldArg, NewF->getArg(oldIdx));
        } else {
            // 第 5+ 个：从结构体 load。在入口处插入 gep + load。
            IRBuilder<> GepB(InsertPt);
            Value *geps[] = {
                ConstantInt::get(Type::getInt32Ty(M.getContext()), 0),
                ConstantInt::get(Type::getInt32Ty(M.getContext()), packIdx)};
            Value *elemPtr = GepB.CreateGEP(PackTy, PackPtr, geps,
                                            "__wide." + OldArg.getName());
            Value *loaded = GepB.CreateLoad(OldArg.getType(), elemPtr,
                                            "__wide.ld." + OldArg.getName());
            replacements.emplace_back(&OldArg, loaded);
            ++packIdx;
        }
        ++oldIdx;
    }

    // 应用替换
    for (auto &[old, neu] : replacements)
        old->replaceAllUsesWith(neu);

    // 旧 F 已经没有函数体了（被 splice 走），把它删掉。
    // 但要先清掉旧 F 的所有 use——其实旧 F 在 use 端是被 call 引用的，
    // 那些会在 rewriteCallers 阶段单独处理。这里只确保旧 F 的 body 没了。
    F.dropAllReferences();
    return NewF;
}

// 计算一个调用点需要打包进共享缓冲区的字节数：即第 Threshold 个之后的实参
// allocSize 之和。两条路径共用：
//   - >5 参数路径：Threshold = KEEP_REGS（前 4 个走寄存器，第 5 个起打包）
//   - 变参路径：    Threshold = NumNamed（具名参数之后的变参实参打包）
static unsigned packBytes(CallBase *CB, const DataLayout &DL, unsigned Threshold) {
    unsigned bytes = 0, idx = 0;
    for (Value *arg : CB->args()) {
        if (idx >= Threshold)
            bytes += DL.getTypeAllocSize(arg->getType());
        ++idx;
    }
    return bytes;
}

// 为 caller 在入口块分配一块共享字节缓冲区 [N x i8]，N 为该 caller 所有调用点打包
// 字节数的最大值。同一 caller 的所有调用点（>5 参数 + 变参混合）共用这块缓冲区：每个
// 调用点在发起 call 前从偏移 0 开始完整覆写，call 返回后即不再使用，窗口互不重叠（BPF
// 同步执行无并发；递归因每帧独立栈帧而安全）。这样把"每个调用点独立 alloca"导致的栈
// 膨胀（BPF 后端不做栈槽复用，直接累加）压缩为单个 alloca。
static AllocaInst *allocSharedPackBuf(Function *Caller, unsigned MaxBytes) {
    IRBuilder<> EntryB(&Caller->getEntryBlock().front());
    Type *BufTy = ArrayType::get(Type::getInt8Ty(Caller->getContext()), MaxBytes);
    return EntryB.CreateAlloca(BufTy, nullptr, "__pack.buf");
}

// 改写一个调用点：把第 Threshold 个之后的实参按 allocSize 累加字节偏移 store 进
// caller 共享的字节缓冲区 SharedBuf，前 Threshold 个实参原样传入，末尾追加 SharedBuf
// 指针，重建调用。三条路径共用：
//   - >5 参数路径：Threshold = KEEP_REGS。callee 侧用具名 packed 结构体 GEP+Load，
//     packed 字段偏移 = allocSize 之和，与本处字节偏移自洽。
//   - 变参路径：    Threshold = NumNamed。callee 侧 va_arg 按 DL.getTypeAllocSize(T)
//     推进指针，与本处字节偏移自洽。
//   - 间接调用路径：Threshold = KEEP_REGS。callee 是函数指针变量（Value *，非 Function），
//     但只要它最终指向某个被本 pass 改写过的函数， callee 读 pack 的布局与前两条路径
//     完全一致，故打包规则相同、无需知道 callee 具体是谁。
void rewriteCallSitePacked(CallBase *CB, Value *Callee, Value *SharedBuf,
                           unsigned Threshold) {
    IRBuilder<> B(CB);
    const DataLayout &DL = CB->getModule()->getDataLayout();
    Type *I8 = Type::getInt8Ty(CB->getContext());

    SmallVector<Value *, 8> newArgs;
    unsigned idx = 0;
    unsigned offset = 0;   // 共享缓冲区字节偏移（= packed 结构体字段偏移）
    for (Value *arg : CB->args()) {
        if (idx < Threshold) {
            newArgs.push_back(arg);
        } else {
            // 按 allocSize 累加字节偏移，逐字段 store（packed 布局）
            Value *elemPtr = B.CreateConstGEP1_32(I8, SharedBuf, offset, "__pack.field");
            B.CreateStore(arg, elemPtr);
            offset += DL.getTypeAllocSize(arg->getType());
        }
        ++idx;
    }
    newArgs.push_back(SharedBuf);

    // 创建新调用。BPF 不支持异常/landingpad，IR 里只会出现 CallInst。
    // 显式传 FunctionType：间接调用的 callee 是 ptr 变量，opaque pointer 下
    // IRBuilder 无法从 Callee 推断签名；且原调用点若是变参（(i32,...)），改写后必须
    // 变成定参（前 Threshold 个参数类型 + 末尾 ptr），否则 BPF 后端仍会拒绝变参调用。
    // 故这里用 newArgs 的实际类型重新构造一个【非变参】FunctionType。
    auto *CI = cast<CallInst>(CB);
    SmallVector<Type *, 8> newArgTys;
    for (Value *V : newArgs)
        newArgTys.push_back(V->getType());
    FunctionType *NewFTy = FunctionType::get(CI->getFunctionType()->getReturnType(),
                                             newArgTys, false /*非变参*/);
    CallInst *NC = B.CreateCall(NewFTy, Callee, newArgs);
    NC->setTailCallKind(CI->getTailCallKind());
    CI->replaceAllUsesWith(NC);
    CI->eraseFromParent();
}

// 改写一个 6 参 syscall 调用点（callee = inttoptr(ConstantInt)，BPF 后端编为
// `call <imm>`（src_reg=0））为「5 参 IR call + 前置内联 asm 写 r0 = 第6参」：
//   1. 在 call 之前插入一条 side-effect 内联 asm，input "r" 放第 6 参，clobber
//      r1..r9。BPF 后端只有 r0 不在 clobber 列表里且能承接 input，因此 LLVM 寄存器
//      分配器别无选择，把第 6 参落到 r0；clobber r1..r5 顺带让后端自动 spill/reload
//      原 5 个实参，重建 call 时再恢复 r1..r5（实测见 t10.c 反汇编）。这等价于
//      "call 前把第 6 参写进 r0"，但完全在 IR 层完成，无需改 BPF 后端。
//   2. 重建 call：保留原 callee（inttoptr id），仅传前 5 个实参，返回类型不变。
//      原 call imm（BPF_CALL_*）此时变成 5 参 syscall 形式。call 执行后 r0 自然
//      被 syscall 返回值覆盖，与之前写入的第 6 参没有冲突（syscall 不读自己写的 r0
//      输入，VM do_xxx 直接读 r0 既是参数也覆写为返回值）。
//
// 实参 ≤5 个的 syscall 形式 call site 不进本函数（不需要写 r0），由本 pass 完全
// 保留原样，BPF 后端本就支持 ≤5 参的 syscall 形式调用。
static void rewriteCallSiteSyscall6(CallBase *CB, Value *Callee) {
    IRBuilder<> B(CB);
    LLVMContext &Ctx = CB->getContext();
    Type *I64Ty = Type::getInt64Ty(Ctx);

    // 第 6 个实参（索引 5）。BPF 寄存器是 64 位；若实参不是 i64，按 musl __scc()
    // 语义 sign-extend 到 i64。实际 musl 的 __syscall6 所有参数已经是 long。
    Value *arg6 = CB->getArgOperand(5);
    if (arg6->getType() != I64Ty)
        arg6 = B.CreateSExt(arg6, I64Ty, "__syscall.arg6");

    // 构造 InlineAsm：void(i64)；约束串 "r,~{r1},...,~{r9}"。
    // 空汇编体、side-effect=true 防止被优化器删除。
    FunctionType *AsmFTy = FunctionType::get(Type::getVoidTy(Ctx), {I64Ty}, false);
    InlineAsm *IA = InlineAsm::get(
        AsmFTy, /*AsmString=*/"", /*Constraints=*/"r,~{r1},~{r2},~{r3},~{r4},~{r5},~{r6},~{r7},~{r8},~{r9}",
        /*hasSideEffects=*/true);
    B.CreateCall(IA, {arg6}, "__syscall.setarg6");

    // 重建 5 参 call：原 callee（inttoptr id）+ 前 5 个实参。BPF 后端将编为
    // `call <imm>`（src_reg=0），即 5 参 syscall 形式；第 6 参通过 r0 传递。
    SmallVector<Value *, 8> newArgs;
    SmallVector<Type *, 8> newArgTys;
    for (unsigned i = 0; i < 5; ++i) {
        Value *a = CB->getArgOperand(i);
        newArgs.push_back(a);
        newArgTys.push_back(a->getType());
    }
    FunctionType *NewFTy = FunctionType::get(CB->getFunctionType()->getReturnType(),
                                             newArgTys, false /*非变参*/);
    auto *CI = cast<CallInst>(CB);
    CallInst *NC = B.CreateCall(NewFTy, Callee, newArgs);
    NC->setTailCallKind(CI->getTailCallKind());
    CI->replaceAllUsesWith(NC);
    CI->eraseFromParent();
}

// 一个待改写的调用点：调用谁（Callee：直接调用是 NewF，间接调用是函数指针 Value）、
// 第几个实参起打包（Threshold）。
struct PackSite {
    CallBase *CB;
    Value *Callee;     // 直接调用 = NewF；间接调用 = 原 callee（Value*）
    unsigned Threshold;
    bool IsSyscall = false;   // syscall 6 参特例走 rewriteCallSiteSyscall6
};

// 按 caller 聚合的调用点表，及每个 caller 所需的最大打包字节数。
using SiteMap = SmallDenseMap<Function *, SmallVector<PackSite, 8>>;
using BytesMap = SmallDenseMap<Function *, unsigned>;

// 收集调用某（旧）函数 OldF 的所有【直接】call site，按 caller 聚合到 byCaller，并更新各
// caller 的最大打包字节数 maxBytes。Threshold 决定第几个实参起需要打包（>5 路径用
// KEEP_REGS，变参路径用 NumNamed）。两条路径共用此逻辑。
static void collectCallSites(Function *OldF, Function *NewF, unsigned Threshold,
                             const DataLayout &DL, SiteMap &byCaller,
                             BytesMap &maxBytes) {
    for (User *U : OldF->users()) {
        auto *CB = dyn_cast<CallBase>(U);
        if (!CB || CB->getCalledFunction() != OldF)
            continue;
        Function *Caller = CB->getFunction();
        byCaller[Caller].push_back({CB, NewF, Threshold});
        unsigned b = packBytes(CB, DL, Threshold);
        if (b > maxBytes[Caller])
            maxBytes[Caller] = b;
    }
}

// 收集所有【间接】调用点（callee 是函数指针变量、getCalledFunction()==null）中，需要
// 打包的。两种情况：
//   - 定参调用点，实参 >5：Threshold = KEEP_REGS（前 4 个走寄存器，第 5 个起打包）。
//   - 变参调用点 (T0..Tn, ...)：Threshold = 具名参数个数 n（具名参数之后的变参实参打包）。
//     调用点的 FunctionType->getNumParams() 给出具名参数个数。
// 关键洞察：实参类型与个数信息全在调用点本身，改写时【不需要】知道 callee 是谁——
// 只要 callee 最终指向某个被本 pass 改写过的函数，它读 pack 的布局就与直接调用一致。
static void collectIndirectCallSites(Module &M, const DataLayout &DL,
                                     SiteMap &byCaller, BytesMap &maxBytes) {
    for (Function &F : M) {
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                auto *CB = dyn_cast<CallBase>(&I);
                if (!CB)
                    continue;
                if (CB->getCalledFunction() != nullptr)
                    continue;   // 直接调用，已由 collectCallSites 处理

                // 【syscall 路径】：callee 是 inttoptr(ConstantInt)，BPF 后端编为
                // `call <imm>`（src_reg=0）的 syscall 形式。最多 6 参：前 5 个走
                // r1..r5，第 6 个通过前置内联 asm 写到 r0（见 rewriteCallSiteSyscall6）。
                // 不走 packed struct 路径。
                if (isSyscallCallee(CB->getCalledOperand())) {
                    unsigned nargs = CB->arg_size();
                    if (nargs > 6) {
                        // syscall 硬上限 6 参；超出直接报编译期错误。
                        errs() << "BpfWideArgs: error: syscall call site has "
                               << nargs << " arguments (max 6)\n";
                        report_fatal_error("BPF syscall with > 6 arguments");
                    }
                    if (nargs < 6)
                        continue;   // ≤5 参的 syscall 形式调用原本就合法，无需改写
                    // 恰好 6 参：走 syscall 路径
                    Function *Caller = CB->getFunction();
                    byCaller[Caller].push_back(
                        {CB, CB->getCalledOperand(), /*Threshold=*/6,
                         /*IsSyscall=*/true});
                    continue;
                }

                unsigned threshold;
                if (CB->getFunctionType()->isVarArg()) {
                    // 变参：具名参数之后的变参实参打包
                    threshold = CB->getFunctionType()->getNumParams();
                } else {
                    // 定参：只有 >5 参才需要打包
                    if (CB->arg_size() <= BPF_ARG_LIMIT)
                        continue;
                    threshold = KEEP_REGS;
                }
                // 变参调用点若变参实参为 0（只有具名参数），无需打包
                if (threshold >= CB->arg_size())
                    continue;
                Function *Caller = CB->getFunction();
                byCaller[Caller].push_back({CB, CB->getCalledOperand(), threshold});
                unsigned b = packBytes(CB, DL, threshold);
                if (b > maxBytes[Caller])
                    maxBytes[Caller] = b;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// sret 剥离：让 BPF 后端能接受"返回结构体"的函数。
//
// clang 在 IR 层已经把 struct 返回降级成 sret 指针形式：
//   struct P f(int)      →    void f(ptr sret(%P), int)
// 即第一个参数是 caller 分配的输出缓冲区指针，函数往里写结果。
// 这本就是合法的 BPF 代码（5 参数内的 void 函数 + ptr 参数），
// 但 BPF 后端见到 sret 属性就报 "aggregate returns are not supported"。
//
// 解决：在 BPF 后端之前，把 sret 属性从【函数签名】和【所有调用点】
// 同时剥掉。函数语义不变（仍往指针写结果），只是丢了那个标记。
// ---------------------------------------------------------------------------
bool stripSret(Module &M) {
    bool changed = false;

    // 1. 遍历所有有 sret 参数的函数，剥函数签名上的 sret
    SmallVector<Function *, 16> funcs;
    for (Function &F : M) {
        if (F.isDeclaration())
            continue;
        for (unsigned i = 0; i < F.arg_size(); ++i) {
            if (F.hasParamAttribute(i, Attribute::StructRet)) {
                funcs.push_back(&F);
                break;
            }
        }
    }
    if (funcs.empty())
        return false;

    for (Function *F : funcs) {
        // 逐个参数剥 sret（保留其它属性如 noalias/nocapture）
        for (unsigned i = 0; i < F->arg_size(); ++i) {
            if (F->hasParamAttribute(i, Attribute::StructRet)) {
                F->removeParamAttr(i, Attribute::StructRet);
                changed = true;
            }
        }
    }

    // 2. 剥所有 call/invoke 调用点上的 sret（callee 属性变了，调用点要同步）
    for (Function *F : funcs) {
        for (User *U : F->users()) {
            if (auto *CB = dyn_cast<CallBase>(U)) {
                if (CB->getCalledFunction() != F)
                    continue;
                for (unsigned i = 0; i < CB->arg_size(); ++i) {
                    if (CB->paramHasAttr(i, Attribute::StructRet)) {
                        CB->removeParamAttr(i, Attribute::StructRet);
                        changed = true;
                    }
                }
            }
        }
    }

    return changed;
}

// ===========================================================================
// 聚合值参数归一化（统一成裸 ptr，恒占 1 个寄存器）
//
// BPF 后端 LowerFormalArguments 对"会被展开成 >1 个 64 位寄存器的参数"会撑爆
// 5-参数硬上限。clang 对按值聚合参数分两路降级，本 pass 把两路都归一到裸 ptr：
//
//   路径 A（大聚合，≥3 个 word，如 string 24B、Quad 32B）：
//     clang 已 lower 成 `ptr byval(%T) align N %x`——参数类型已是 ptr，caller
//     已 memcpy 实参到栈临时再传指针，callee 直接当指针用（GEP/load）。本 pass
//     只需【剥 byval 属性】（BPF 后端见 byval 报 "pass by value not supported"）。
//     不改类型、不改函数体、不改 call site 的实参——只删属性。caller 的 memcpy
//     不会被优化器误删（callee 收到无属性 ptr，优化器无法证其不写，保守保留）。
//
//   路径 B（小聚合，≤2 个 word，如 std::pair={i64,i64}、__bit_iterator=[2 x i64]、
//     {i32,i32}=8B、i128）：clang 不走 byval，直接用【聚合值类型】作参数类型：
//       long f(std::pair<long,long> p)  →  long f([2 x i64] %p)
//     BPF 后端把这种值类型按元素/字段个数展开成多个寄存器：[2 x i64] 占 2 个。
//     于是 __count(__bit_iterator, __bit_iterator, value, proj) = 2+2+1+1 = 6
//     寄存器 > 5 → "too many arguments"。本 pass 把它【重建签名 + 搬函数体 +
//     入口 load + call site alloca/store】降级成裸 ptr（与路径 A 终态一致）。
//
// 两路径不重叠（一个已是 ptr，一个不是），无顺序依赖，无瞬态属性——合并前是
// 两个 pass（lowerAggregateParams 加 byval、stripByval 剥 byval）背靠背跑造一个
// 只活几毫秒的中间 byval，纯粹为复用；现直接产出终态裸 ptr，消除中间态。
//
// 典型触发 B：bitset::count → std::__count<...>(__bit_iterator, __bit_iterator, ...)
// （bitset 头里 bit_iterator 是 2-word 聚合）。format 的 __write_string/__format_integer
// 同理（多参 + 聚合）。
//
// 降级判据（needsLowering，针对路径 B 的值类型）：BPF 后端会展开成 >1 个寄存器
// 的类型——①聚合（ArrayType/StructType，按构成展开，哪怕 {i32,i32}=8B）；②i128
// 及更大标量（>8B，拆成 2 个 64 位寄存器）。排除指针（含路径 A 已降级的 ptr
// byval）、≤64 位标量、向量（向量走单独路径，少见且 BPF 后端有原生支持）。
//
// 语义不变：按值传递 = caller 拷贝一份给 callee，callee 拿到副本。两路径转成 ptr
// 后都满足——路径 A 本就是 ptr（caller memcpy）；路径 B caller store 值到 alloca、
// callee load 出值。callee 对参数的修改不得影响 caller（C++ 按值语义）。
// ===========================================================================
// 判断一个参数类型是否需要降级为 ptr byval。
// 判据：BPF 后端 LowerFormalArguments 会把它展开成 >1 个寄存器的类型。
//   - 聚合（ArrayType/StructType）：按元素/字段个数展开。哪怕 {i32,i32}=8B 也按 2 个
//     寄存器算（实测 BPF 后端对聚合按构成展开，不按整体大小）。
//   - i128（及更大标量）：占 2 个 64 位寄存器。
// 排除：指针（含已降级的 ptr byval）、≤64 位标量、向量（向量走单独路径，少见且 BPF 后端
// 有原生支持）。
static bool needsLowering(Type *T, const DataLayout &DL) {
    if (T->isPointerTy())
        return false;
    if (T->isArrayTy() || T->isStructTy())
        return true;
    // 标量但 >8 字节（i128 等）：BPF 后端拆成多个寄存器
    if (T->isIntegerTy() && DL.getTypeAllocSize(T) > 8)
        return true;
    return false;
}

// 把 callee 的聚合【值】参数（如 [2 x i64] shared_ptr）的 use 重写成通过【指针】参数访问。
//
// 背景：clang 对 by-value 非平凡聚合生成值类型参数（[2 x i64]），callee 体里先
// `store %arg, ptr %local` 把值拷贝到可寻址内存，再 move/copy %local。若简单 load
// 出值替换 %arg，move 作用于 load 副本，无法置空 caller 源对象 → 引用计数错乱
// （见路径 B 整体注释及 eliminateByvalScalarTemporaries 的 #207686 注释）。
//
// 正确做法（模拟 x86 invisible-reference ABI）：让指针参数直接代表「值的存储位置」
// （指向 caller 的源对象）。对每条 use：
//   - `store T %arg, ptr %dst`（把值拷贝到本地 %dst）：消除该 store，后续对 %dst 的
//     use 全部替换成 %newarg（%dst 成为指针参数的别名）。这样函数体里对 %dst 的
//     move/copy/load 直接作用于 caller 源对象。
//   - 其它 use（直接当值用）：在 use 前插 load T, ptr %newarg，替换 use。
//
// 典型 clang 生成模式只有第一种 use（非平凡聚合先拷贝到本地再操作），故走消除路径。
static void rewriteValueParamUsesToPointer(Function &F, Instruction *InsertPt,
                                           Argument *OldArg, Value *NewArg) {
    Type *valTy = OldArg->getType();

    // 收集所有 use（边遍历边改会失效迭代器）。
    SmallVector<Use *, 8> uses;
    for (Use &U : OldArg->uses())
        uses.push_back(&U);

    // 兜底 load（懒创建）：所有「直接值 use」共享同一个 load，避免多次读且保证
    // InsertPt 早于所有 use。仅当存在非 store-to-local 的 use 时才创建。
    Value *fallbackLoad = nullptr;
    auto getFallbackLoad = [&]() -> Value * {
        if (!fallbackLoad) {
            IRBuilder<> B(InsertPt);
            fallbackLoad = B.CreateLoad(valTy, NewArg, "__agg.ld." + OldArg->getName());
        }
        return fallbackLoad;
    };

    for (Use *U : uses) {
        User *UR = U->getUser();
        auto *SI = dyn_cast<StoreInst>(UR);
        // 模式：store T %oldarg, ptr %dst —— %oldarg 是被存的值（operand 0）。
        if (SI && SI->getValueOperand() == OldArg) {
            Value *dst = SI->getPointerOperand();
            // clang 对 `return __iter`（by-value 聚合参数的返回）生成：
            //   %tmp = alloca T
            //   store %arg, ptr %tmp.field0   ; %dst = gep(%tmp, 0, 0)
            //   call T::T(sret, %tmp)          ; move from %tmp（alloca base，非 %dst）
            // 简单 RAUW %dst（gep）不影响 %tmp，move 从未初始化 %tmp 读出垃圾
            // （directory_iterator::begin/end 这类 free function return by-value
            // 聚合即触发，range-for begin() 拿到空迭代器，循环体不执行）。
            // 当 %dst 是 gep(alloca, ...) 且字节 offset 0、且 gep 取整个 alloca
            // （大小相等 = alloca 是单字段聚合、store 即整体赋值），改 RAUW alloca base。
            if (auto *GEP = dyn_cast<GetElementPtrInst>(dst)) {
                Value *base = GEP->getPointerOperand()->stripPointerCasts();
                if (auto *AI = dyn_cast<AllocaInst>(base)) {
                    const DataLayout &DL = F.getParent()->getDataLayout();
                    APInt off(DL.getIndexSizeInBits(GEP->getPointerAddressSpace()), 0);
                    if (GEP->accumulateConstantOffset(DL, off) && off.isZero() &&
                        DL.getTypeAllocSize(AI->getAllocatedType()) ==
                            DL.getTypeAllocSize(GEP->getResultElementType())) {
                        dst = AI;
                    }
                }
            }
            // 消除拷贝：后续对 %dst 的 use 全部替换成 %newarg（指针参数别名）。
            // %dst 通常是 alloca；它的所有 use（load/store/gep/传入 call 等）改成
            // 操作 %newarg 指向的 caller 源对象。
            dst->replaceAllUsesWith(NewArg);
            SI->eraseFromParent();
            continue;
        }
        // 其它 use（直接当值用，如再传给另一个 [2 x i64] 参数的 call）：替换成从指针
        // load 出的值。值传递语义，但 move 不置空源 —— 此场景下源不会被 move，故无
        // 计数问题。理论上 clang 对聚合值参数只生成 store-to-local 模式，此为兜底。
        U->set(getFallbackLoad());
    }
}

// 收集函数里"需要降级的值类型聚合参数"的下标（路径 B：非 byval、非 ptr 的聚合
// 值类型）。已是 byval 的（路径 A，大聚合）不在此收集——它们只剥属性、不重建签名。
static SmallVector<unsigned, 4> collectAggregateValueParams(Function &F, const DataLayout &DL) {
    SmallVector<unsigned, 4> idxs;
    for (unsigned i = 0; i < F.arg_size(); ++i) {
        if (F.hasParamAttribute(i, Attribute::ByVal))
            continue;  // 路径 A（已是 byval ptr），走剥属性分支
        Type *ty = F.getFunctionType()->getParamType(i);
        if (needsLowering(ty, DL))
            idxs.push_back(i);
    }
    return idxs;
}

bool lowerAggregateParams(Module &M) {
    bool changed = false;

    // ===== 路径 A：剥大聚合的 byval 属性（参数已是 ptr，不改类型/函数体/call site 实参）=====
    // clang 已 lower 成 ptr byval(%T)，caller 已 memcpy 临时拷贝传指针，callee 当指针用。
    // 只需删 byval 这个 BPF 后端不认的标记。覆盖直接调用 / 间接调用 / 外部声明 callee，
    // 故 call site 遍历全部 CallBase（不只 F->users()）。
    //
    // caller 的 memcpy 不会被优化器误删：callee 收到无属性 ptr，优化器无法证其不写
    // （byval 内存 callee 可读写），保守保留——正是 C++ 按值语义所需。
    // 必须先于路径 B 的"重建签名"跑：路径 B 新建的函数 copyAttributesFrom 会原样
    // 带过来 byval（若有），统一在这里清掉更干净。
    for (Function &F : M) {
        for (unsigned i = 0; i < F.arg_size(); ++i) {
            if (F.hasParamAttribute(i, Attribute::ByVal)) {
                F.removeParamAttr(i, Attribute::ByVal);
                changed = true;
            }
        }
    }
    for (Function &F : M) {
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                auto *CB = dyn_cast<CallBase>(&I);
                if (!CB)
                    continue;
                for (unsigned i = 0; i < CB->arg_size(); ++i) {
                    if (CB->paramHasAttr(i, Attribute::ByVal)) {
                        CB->removeParamAttr(i, Attribute::ByVal);
                        changed = true;
                    }
                }
            }
        }
    }

    // ===== 路径 B：小聚合成值参数降级成裸 ptr（重建签名 + 搬函数体 + 入口 load + call site store）=====
    // clang 直接用聚合值类型作参数类型（无 byval），BPF 后端按构成展开成多个寄存器。
    // 第一遍：找出需要改签名的函数（至少一个聚合值参数）。重建 FunctionType 必须
    // 新建函数搬函数体（LLVM Function 不能就地改类型），先收集再统一处理，避免
    // 边遍历边改迭代器失效。
    struct Job { Function *OldF; Function *NewF; SmallVector<unsigned, 4> agIdxs; };
    SmallVector<Job, 16> jobs;
    const DataLayout &DL = M.getDataLayout();
    for (Function &F : M) {
        if (isInternalOrIntrinsic(F))
            continue;
        SmallVector<unsigned, 4> idxs = collectAggregateValueParams(F, DL);
        if (idxs.empty())
            continue;
        // 构造新签名：聚合值参数类型 T → 裸 ptr（不产 byval，直接到终态）。
        SmallVector<Type *, 8> newArgTys;
        for (unsigned i = 0; i < F.arg_size(); ++i) {
            Type *pTy = F.getFunctionType()->getParamType(i);
            newArgTys.push_back(needsLowering(pTy, DL)
                                    ? PointerType::getUnqual(F.getContext())
                                    : pTy);
        }
        FunctionType *newFTy = FunctionType::get(F.getReturnType(), newArgTys, F.isVarArg());
        Function *NewF = Function::Create(newFTy, F.getLinkage(), F.getAddressSpace(),
                                           "__bpf_agg_tmp_" + F.getName(), &M);
        NewF->copyAttributesFrom(&F);
        NewF->setVisibility(F.getVisibility());
        NewF->setComdat(F.getComdat());
        NewF->setSection(F.getSection());
        NewF->setDSOLocal(F.isDSOLocal());
        jobs.push_back({&F, NewF, idxs});
        changed = true;
    }
    if (jobs.empty())
        return changed;

    // 第二遍：搬迁函数体（有定义时），入口 load 重建聚合值。
    for (auto &j : jobs) {
        Function *F = j.OldF;
        Function *NewF = j.NewF;
        if (F->isDeclaration()) {
            // 声明（prototype，无定义体）：只换签名。真正定义在另一 TU（那里本 pass
            // 同样改写，签名一致）。调用点改写统一在第三遍处理。
            NewF->takeName(F);
            F->dropAllReferences();
            continue;
        }
        // 搬函数体
        NewF->splice(NewF->end(), F);
        NewF->takeName(F);

        // 入口插入 load 重建聚合值：把对旧聚合参数（值）的 use 替换成 load 出的值。
        BasicBlock &Entry = NewF->front();
        Instruction *InsertPt = &Entry.front();
        while (InsertPt && (isa<PHINode>(InsertPt) || isa<AllocaInst>(InsertPt)))
            InsertPt = InsertPt->getNextNode();
        if (!InsertPt)
            InsertPt = Entry.getTerminator();

        std::vector<std::pair<Argument *, Value *>> replacements;
        SmallSet<unsigned, 8> aggSet;
        aggSet.insert(j.agIdxs.begin(), j.agIdxs.end());
        unsigned idx = 0;
        for (Argument &OldArg : F->args()) {
            Argument *NewArg = NewF->getArg(idx);
            if (aggSet.count(idx)) {
                rewriteValueParamUsesToPointer(*NewF, InsertPt, &OldArg, NewArg);
            } else {
                replacements.emplace_back(&OldArg, NewArg);
            }
            ++idx;
        }
        for (auto &[old, neu] : replacements)
            old->replaceAllUsesWith(neu);
        F->dropAllReferences();
    }

    // 第三遍：改写所有 call/invoke 调用点。聚合实参 → store 到临时 alloca，传裸指针。
    // 关键：先【RAUW 前】收集每个 OldF 的所有调用点，否则 RAUW 会因函数类型不同给
    // callee operand 套一层 bitcast，getCalledFunction() 返回 null，定位不到 job。
    // 收集时记录 call site → 它调用的 OldF（指针，RAUW 前的原 callee）。
    DenseMap<CallBase *, Function *> sites;
    for (auto &j : jobs) {
        for (User *U : j.OldF->users()) {
            auto *CB = dyn_cast<CallBase>(U);
            if (!CB)
                continue;
            // 只认直接调用本 OldF 的（排除传给别的 bitcast 等非调用 use）
            if (CB->getCalledFunction() != j.OldF)
                continue;
            sites[CB] = j.OldF;
        }
    }

    // 建立 OldF → job 映射，便于由 call site 的 OldF 反查 agIdxs / NewF。
    DenseMap<Function *, Job *> jobByOld;
    for (auto &j : jobs)
        jobByOld[j.OldF] = &j;

    // 现在改写每个 call site：聚合实参是【值类型】（[2 x i64]/{...}/i128），不是 ptr。
    // callee 侧已把值参数改成裸 ptr（入口 load 出值或直接用指针，见 rewriteValueParamUsesToPointer）。
    // caller 侧分两种情况传实参：
    //   (a) 实参是 `load T, ptr %src`（clang 对非平凡 by-value 聚合的典型模式：caller
    //       copy/move 构造一个临时 %src，再 load 出值传给 callee）。此时直接传 %src 指针，
    //       让 callee 与 caller 共享同一存储 —— callee 内部的 move 构造作用于 %src，
    //       置空源，caller 后续析构 %src 是 no-op，引用计数正确（模拟 x86 invisible-ref）。
    //   (b) 实参是其它形式（平凡聚合直接构造的值，或另一 callee 的返回值）：在入口建
    //       alloca、call 前 store 值、传 alloca 指针。平凡类型按位拷贝语义正确。
    // 不加 byval 属性——直接产裸 ptr 终态。
    //
    // alloca 必须插在【caller 入口块】——BPF 后端要求所有 alloca 集中在入口块（static
    // alloca），非入口块的固定大小 alloca 会被拒绝（见 BpfVlaPass 的注释）。若 call
    // 在循环/中间块，把 alloca 插在 call 前会让它脱离入口块。store 仍留在 call 前
    // （每次调用都要覆写临时），alloca 的入口块布局保证后端接受。
    for (auto &[CB, OldF] : sites) {
        Job *j = jobByOld[OldF];
        Function *NewF = j->NewF;
        Function *Caller = CB->getFunction();
        // 先切 callee 到 NewF（NewF 签名里聚合参数已是裸 ptr）
        CB->setCalledFunction(NewF->getFunctionType(), NewF);
        // 为每个聚合参数处理实参：load 源 → 传源指针；否则 alloca+store。
        for (unsigned i : j->agIdxs) {
            Value *arg = CB->getArgOperand(i);
            if (auto *LI = dyn_cast<LoadInst>(arg)) {
                // (a) 实参是 load：传源指针（caller 临时/源对象的地址）。
                CB->setArgOperand(i, LI->getPointerOperand());
                continue;
            }
            // (b) 实参是直接值：建 alloca 存值传指针。
            Type *aggTy = arg->getType();
            IRBuilder<> EntryB(&Caller->getEntryBlock(), Caller->getEntryBlock().getFirstInsertionPt());
            AllocaInst *tmp = EntryB.CreateAlloca(aggTy, nullptr, "__agg.arg");
            tmp->setAlignment(Align(DL.getABITypeAlign(aggTy)));
            IRBuilder<> B(CB);
            B.CreateStore(arg, tmp);
            CB->setArgOperand(i, tmp);
        }
    }

    // RAUW 残余 use（非 call 的 use，如取地址存 vtable 等）→ NewF。此时 NewF 签名
    // 已定，RAUW 对残余 use 若有类型差会套 bitcast（与 call site 不同，那些 use 不影响
    // 后端代码生成正确性）。
    for (auto &j : jobs)
        j.OldF->replaceAllUsesWith(j.NewF);

    // 第四遍：删除旧函数。RAUW 已把所有 use 转到 NewF，OldF 应无 use——与
    // rewriteFunction/rewriteVarArgFunction 路径一致无条件 erase（那里先 RAUW 再 erase）。
    // 旧版用 if(use_empty()) 守卫，若 RAUW 因故没清空 use 会静默泄漏 OldF，不一致。
    for (auto &j : jobs)
        j.OldF->eraseFromParent();

    return changed;
}

// ===========================================================================
// by-value 非平凡析构参数（std::unique_ptr/std::shared_ptr 等）的 double-free 修复
//
// 背景（上游 LLVM issue #207686）：BPF 后端把能塞进 1~2 个寄存器（≤16B）的非
// 平凡析构 by-value 参数直接降级成 i64 / [2 x i64] 按值传递（unique_ptr=8B→i64、
// shared_ptr=16B→[2 x i64]），而不是按 Itanium C++ ABI 走 invisible-reference
// (ptr 指向 caller 栈临时)。
//
// caller 侧的 IR 模式（lowerAggregateParams 已把 callee 签名改成 ptr 之后）：
//   %tmp = alloca T                          ; 备份临时
//   call T::T(ptr %tmp, ptr %src)            ; move-construct（mangling 含 C1/C2 + OS_）
//   %v  = load T,  ptr %tmp                  ; 取出值
//   store %v, ptr __agg_arg                  ; 转存到 lowerAggregateParams 插入的 alloca
//   call @callee(ptr __agg_arg)              ; callee 拿 ptr，move 出去后置空它自己的 ptr
//   call ~T(ptr %tmp)                        ; ★ 析构备份 %tmp——值仍是原指针→double-free
// %tmp 是多余的"中转"备份：它的内容已交给 callee（callee 通过 __agg_arg 拥有），
// 析构它就再次释放已被 callee move 走的资源。
//
// 修复：在 dtor 前插入 store zeroinitializer, %tmp，把 %tmp 清零让析构 noop。
// 所有 load 都在 dtor 前（备份临时只在调用前被读），清零不破坏正确性。
//
// 识别 %tmp 是"备份临时"而非普通局部对象（两条路径任一满足即处理）：
//   路径 A：存在 call T::T(ptr %tmp, ptr %src) move-construct（mangling 含
//           C1/C2 + OS_<num>_）——%tmp 是从另一个 T 对象 move 出来的备份。普通局部
//           对象（call T::T(ptr %s, i64 a, i64 b)）不走从另一同类型对象 move 构造，
//           这是可靠的区分。再加 benign-use 守卫（见 isBenignTmpUse）排除少数有
//           move-ctor 但非备份的场景。覆盖 ≤16B（unique_ptr 8B + shared_ptr 16B）。
//   路径 B：size ≤ 8 + hasLoad + dtor call——兜底 -O1 已把 move-construct inline 成
//           store、无 call 形式可识别的场景（只覆盖 unique_ptr 8B；16B shared_ptr
//           备份临时在 -O1 后被整体消除，不会进入此路径）。
// ===========================================================================

// 判断 call 是否是对 %tmp 的 move-construct：
//   - mangling 以 _Z 开头，含 "C1"/"C2"（构造函数），且含 "OS" + 数字 + "_"（rvalue ref 参数）
//   - 至少 2 个参数，参数 0 是 %tmp，参数 1 是 ptr 类型
static bool isMoveConstructOf(CallInst *CI, AllocaInst *Tmp) {
    Function *Callee = CI->getCalledFunction();
    if (!Callee)
        return false;
    if (CI->arg_size() < 2)
        return false;
    if (CI->getArgOperand(0) != Tmp)
        return false;
    if (!CI->getArgOperand(1)->getType()->isPointerTy())
        return false;
    StringRef cn = Callee->getName();
    if (!cn.starts_with("_Z"))
        return false;
    if (!cn.contains("C1") && !cn.contains("C2"))
        return false;
    // rvalue ref 参数的 mangling：OS + <num> + _（如 OS2_、OS4_）
    if (!cn.contains("OS"))
        return false;
    return true;
}

// 判断 use 是否"无害"——只读出值（load）、单纯写入（store）、地址 bitcast、或
// lifetime intrinsic / 析构 / move-construct 本身。出现 GEP / atomic / 传入作为
// 非 ctor 的参数（sret/普通参数）等则视为普通局部，跳过避免误伤。
static bool isBenignTmpUse(Value *Tmp, User *U) {
    if (isa<LoadInst>(U) || isa<StoreInst>(U) || isa<BitCastInst>(U))
        return true;
    if (auto *II = dyn_cast<IntrinsicInst>(U)) {
        // llvm.lifetime.start/end 是 ptr nocapture use
        if (II->getIntrinsicID() == Intrinsic::lifetime_start ||
            II->getIntrinsicID() == Intrinsic::lifetime_end)
            return true;
        return false;
    }
    if (auto *CI = dyn_cast<CallInst>(U)) {
        // 允许析构本身 / move-construct / reset(nullptr)。它们都在上面专项判定里。
        Function *Callee = CI->getCalledFunction();
        if (!Callee)
            return false;
        StringRef cn = Callee->getName();
        if (!cn.starts_with("_Z"))
            return false;
        if (cn.contains("D0") || cn.contains("D1") || cn.contains("D2"))
            return true;          // 析构
        if (cn.contains("C1") || cn.contains("C2"))
            return true;          // 构造（含 move-construct）
        if (cn.contains("5reset"))
            return true;          // unique_ptr::reset(nullptr) inline 残留
        return false;
    }
    return false;
}

bool eliminateByvalScalarTemporaries(Module &M) {
    bool changed = false;

    for (Function &F : M) {
        for (BasicBlock &BB : F) {
            SmallVector<std::pair<AllocaInst *, CallInst *>, 8> toErase;

            for (Instruction &I : BB) {
                auto *dtor = dyn_cast<CallInst>(&I);
                if (!dtor || !dtor->getCalledFunction())
                    continue;
                // dtor 返回 void（析构/reset 语义），arg0 是待析构 alloca
                if (!dtor->getCalledFunction()->getReturnType()->isVoidTy())
                    continue;
                if (dtor->arg_size() < 1)
                    continue;
                auto *tmp = dyn_cast<AllocaInst>(dtor->getArgOperand(0));
                if (!tmp)
                    continue;
                // ~T(%tmp)（1 参）或 reset(&%tmp, null/0)（2 参，clang 把 inline 后
                // 的 ~unique_ptr 降级成 reset(nullptr)）。第 2 个及以后的参数必须是
                // 常量 0/null（reset 的"清空"实参），避免误伤 reset(new_ptr) 这类。
                bool constTail = true;
                for (unsigned i = 1; i < dtor->arg_size(); ++i) {
                    if (!isa<Constant>(dtor->getArgOperand(i))) {
                        constTail = false;
                        break;
                    }
                }
                if (!constTail)
                    continue;

                // 只认 C++ 析构（mangling 含 D0/D1/D2）和 unique_ptr::reset(nullptr)
                // （含 "5reset"），避免把 void(ptr alloca, const) 形式的普通调用
                // （lambda operator()、构造 stub 等）误判为析构。
                StringRef cn = dtor->getCalledFunction()->getName();
                if (!(cn.starts_with("_Z") &&
                      (cn.contains("D0") || cn.contains("D1") ||
                       cn.contains("D2") || cn.contains("5reset"))))
                    continue;

                // 两条识别路径（详见函数头注释）：
                //   pathA：存在 call T::T(ptr %tmp, ptr %src) move-construct。
                //   pathB：size ≤ 8（兜底 -O1 已 inline 掉 move-ctor 的场景）。
                // 两条都要求 hasLoad（备份临时的值必被读出交给 callee）。
                bool hasMoveCtor = false;
                for (User *U : tmp->users()) {
                    auto *CI = dyn_cast<CallInst>(U);
                    if (CI && isMoveConstructOf(CI, tmp)) {
                        hasMoveCtor = true;
                        break;
                    }
                }

                bool hasLoad = false;
                for (User *U : tmp->users()) {
                    if (isa<LoadInst>(U)) {
                        hasLoad = true;
                        break;
                    }
                }
                if (!hasLoad)
                    continue;

                const DataLayout &DL = M.getDataLayout();
                uint64_t allocSize = DL.getTypeAllocSize(tmp->getAllocatedType());
                bool pathA = hasMoveCtor;
                bool pathB = (allocSize <= 8);
                if (!pathA && !pathB)
                    continue;

                // pathA 加 benign-use 守卫（避免误伤有 move-ctor 的普通局部对象）；
                // pathB 不加（已在 STL 测试集上验证不误伤，sret 传入等 use 也允许）。
                bool matched = false;
                if (pathA) {
                    bool benign = true;
                    for (User *U : tmp->users()) {
                        if (!isBenignTmpUse(tmp, U)) {
                            benign = false;
                            break;
                        }
                    }
                    if (benign)
                        matched = true;
                }
                if (!matched && pathB)
                    matched = true;
                if (!matched)
                    continue;

                toErase.push_back({tmp, dtor});
            }

            for (auto &[tmp, dtor] : toErase) {
                IRBuilder<> B(dtor);
                B.CreateStore(Constant::getNullValue(tmp->getAllocatedType()), tmp);
                changed = true;
            }
        }
    }

    return changed;
}

// ===========================================================================
// 变参函数（varargs）改写
//
// BPF 后端拒绝任何 isVarArg=true 的函数（BPFISelLowering::LowerFormalArguments
// 里 IsVarArg 检查直接 fail）。本路径把变参函数改写成定参，让后端见不到变参。
//
// ABI（clang 原生 void* 裸指针语义）：
//   callee：R f(T0..Tn, ...) → R f(T0..Tn, ptr __va_base)
//          __va_base 指向 caller 构建的 vararg 内存区（第一个 vararg 的地址）。
//          函数体内 va_list（即 alloca ptr）经 va_start 后存 __va_base。
//   caller：每个 call site 在入口 alloca 一段内存，按变参实参类型布局填值，
//          传首地址作 __va_base。
//
// intrinsic lowering（callee 体内）：
//   va_start(%ap)：store ptr __va_base, ptr %ap   （va_list 指向第一个 vararg）
//   va_arg(%ap,T)：load T, ptr %ap; %next=gep i8,%ap,allocSize(T); store %next,%ap
//   va_end(%ap)  ：no-op
//   va_copy(%d,%s)：%t=load ptr,%s; store %t,%d   （拷贝裸指针值）
// ===========================================================================

// 替换函数体内的 va_start/va_arg/va_end/va_copy。
// VaBase 非 null 时（变参函数改写路径），va_start 绑定到 __va_base；
// VaBase 为 null 时（非变参函数，体内不会有 va_start，只有 va_copy/va_arg/va_end）。
// 返回是否有改动。
static bool lowerVaIntrinsics(Function &F, Value *VaBase) {
    // 先收集所有要处理的指令（边遍历边删不安全）。
    SmallVector<Instruction *, 16> toProcess;
    for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
            if (isa<VAStartInst>(I) || isa<VAEndInst>(I) ||
                isa<VACopyInst>(I) || isa<VAArgInst>(I))
                toProcess.push_back(&I);
        }
    }

    if (toProcess.empty())
        return false;

    const DataLayout &DL = F.getParent()->getDataLayout();

    // 收集 va_arg/va_copy 涉及的指针参数索引：lower 后会通过它们写回推进值，
    // 必须清除 clang 标记的 readonly/readnone/nocapture，否则后续优化器（instcombine）
    // 会把写回的 store 当死存储删掉（pop_arg 的 va_list 参数就因此丢失推进）。
    std::set<unsigned> mutatedArgIndices;
    auto record_arg = [&](Value *V) {
        if (auto *A = dyn_cast<Argument>(V))
            mutatedArgIndices.insert(A->getArgNo());
    };

    for (Instruction *I : toProcess) {
        IRBuilder<> B(I);

        if (auto *VAS = dyn_cast<VAStartInst>(I)) {
            // va_start(%ap)：让 va_list 变量（alloca ptr）存 __va_base。
            // 非变参函数里不应出现 va_start；若出现且无 VaBase 则保留原样（保守）。
            if (VaBase) {
                Value *ApList = VAS->getArgList();
                B.CreateStore(VaBase, ApList);
                I->eraseFromParent();
            }
        } else if (auto *VAA = dyn_cast<VAArgInst>(I)) {
            // va_arg(%ap, T)：VoidPtrBuiltinVaList 下，va_list 是 void*，va_arg 的指针
            // 操作数是「指向 va_list 的指针」(void**)——指向一个保存「当前数据指针」的
            // 可写槽。读出当前 cur、load T、按 allocSize(T) 推进 cur 并写回槽。
            //   CurPtr = *ApOp        // 当前数据指针
            //   Val    = *CurPtr      // 读 T
            //   *ApOp  = CurPtr+step  // 推进，下一次 va_arg 读下一个参数
            // 推进的 store 直接内联，不依赖外部 helper。
            Value *ApOp = VAA->getPointerOperand();
            Type *Ty = VAA->getType();
            Value *CurPtr = B.CreateLoad(PointerType::getUnqual(F.getContext()), ApOp,
                                         "__va.cur");
            Value *Val = B.CreateLoad(Ty, CurPtr, "__va.val");
            uint64_t Step = DL.getTypeAllocSize(Ty);
            Value *Next = B.CreatePtrAdd(CurPtr,
                                         ConstantInt::get(Type::getInt64Ty(F.getContext()), Step),
                                         "__va.next");
            B.CreateStore(Next, ApOp);
            record_arg(ApOp);
            I->replaceAllUsesWith(Val);
            I->eraseFromParent();
        } else if (dyn_cast<VAEndInst>(I)) {
            // va_end：no-op。
            I->eraseFromParent();
        } else if (auto *VAC = dyn_cast<VACopyInst>(I)) {
            // va_copy(%dst, %src)：拷贝裸指针值。
            Value *Dst = VAC->getDest();
            Value *Src = VAC->getSrc();
            Value *Tmp = B.CreateLoad(PointerType::getUnqual(F.getContext()), Src, "__va.cp");
            B.CreateStore(Tmp, Dst);
            record_arg(Dst);
            record_arg(Src);
            I->eraseFromParent();
        }
    }

    // 清除被写回参数的 readonly/readnone/nocapture：lower 后这些参数会被 store，
    // clang 原标的「不修改内存」属性已不成立，留着会让后续 instcombine 删掉推进 store。
    for (unsigned idx : mutatedArgIndices) {
        if (idx < F.arg_size()) {
            F.removeParamAttr(idx, Attribute::ReadOnly);
            F.removeParamAttr(idx, Attribute::ReadNone);
            F.removeParamAttr(idx, Attribute::NoCapture);
        }
    }
    // 函数级的 readonly/readnone 也得清（pop_arg 整体被标 readonly）。
    F.removeFnAttr(Attribute::ReadOnly);
    F.removeFnAttr(Attribute::ReadNone);
    return true;
}

// 改写一个变参函数：构造新签名（原具名参数 + 末尾 ptr __va_base）。
//   - 有函数体（定义）：搬迁函数体，把旧具名参数映射到新参数，lower 体内 va intrinsic。
//   - 纯声明（prototype）：只改签名（创建新声明），无 body 可搬/无 intrinsic 可 lower。
// 返回新 Function*（旧的会被 dropAllReferences，由 run() 统一删除）。
static Function *rewriteVarArgFunction(Function &F) {
    Module &M = *F.getParent();

    // 1. 构造新参数类型表：原具名参数原样 + 末尾一个 ptr（__va_base）。
    SmallVector<Type *, 8> newArgTys;
    for (unsigned i = 0; i < F.arg_size(); ++i)
        newArgTys.push_back(F.getFunctionType()->getParamType(i));
    newArgTys.push_back(PointerType::getUnqual(M.getContext()));

    FunctionType *newFTy = FunctionType::get(F.getReturnType(), newArgTys, false);

    // 2. 创建新函数（临时名，最后 takeName 拿回原名）。
    Function *NewF = Function::Create(
        newFTy, F.getLinkage(), F.getAddressSpace(),
        "__bpf_va_tmp_" + F.getName(), &M);

    NewF->copyAttributesFrom(&F);
    NewF->setVisibility(F.getVisibility());
    NewF->setComdat(F.getComdat());
    NewF->setSection(F.getSection());
    NewF->setDSOLocal(F.isDSOLocal());

    if (F.isDeclaration()) {
        // 纯声明：只改签名，无 body 可搬。
        NewF->takeName(&F);
        F.dropAllReferences();
        return NewF;
    }

    // 3. 搬迁函数体。
    NewF->splice(NewF->end(), &F);
    NewF->takeName(&F);

    // 4. 把旧具名参数映射到新参数（前 N 个一一对应）。
    //    新增的末尾参数 __va_base 留给 lowerVaIntrinsics 用。
    unsigned oldIdx = 0;
    for (Argument &OldArg : F.args()) {
        OldArg.replaceAllUsesWith(NewF->getArg(oldIdx));
        ++oldIdx;
    }

    // 5. lower 体内所有 va intrinsic，用末尾参数作 __va_base。
    Value *VaBase = NewF->getArg(NewF->arg_size() - 1);
    lowerVaIntrinsics(*NewF, VaBase);

    F.dropAllReferences();
    return NewF;
}

// 改写变参调用点的逻辑已统一到 rewriteCallSitePacked（Threshold = NumNamed），
// 故此处不再需要单独的 rewriteVarArgCallSite。

struct BpfWideArgsPass : PassInfoMixin<BpfWideArgsPass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        bool changed = false;

        // 第 0 遍：剥离 sret + 归一化聚合参数，让"返回结构体"和"按值传结构体参数"的函数
        // 都能编译。独立于 >5 参数处理，可叠加（sret/聚合参数指针也算一个参数）。
        // lowerAggregateParams 内含两条子路径：路径 A 剥大聚合的 byval 属性（参数已是 ptr）；
        // 路径 B 把小聚合成值参数重建为裸 ptr（恒占 1 寄存器）。两路径参数不重叠。
        changed |= stripSret(M);
        changed |= lowerAggregateParams(M);

        // ============ 第一阶段：函数体改写（签名 + 体内）============
        // 两条路径互斥（needsRewrite 排除 isVarArg；isVarArgFunction 只取变参），分别
        // 改写 callee 的签名与函数体，得到 {旧F → 新F} 映射。调用点改写推迟到第二阶段
        // 统一处理（这样才能让混合 caller 共用单块缓冲区）。

        // --- >5 参数路径：>5 个参数的非变参函数。---
        struct ToRewrite { Function *F; Function *NewF; };
        SmallVector<ToRewrite, 16> work;
        for (Function &F : M) {
            if (!needsRewrite(F))
                continue;
            StructType *PackTy = buildPackType(F);
            work.push_back({&F, rewriteFunction(F, PackTy)});
            changed = true;
        }

        // --- 变参路径：isVarArg 的函数（含定义 / prototype）。---
        SmallVector<ToRewrite, 16> vaWork;
        for (Function &F : M) {
            if (!isVarArgFunction(F))
                continue;
            vaWork.push_back({&F, rewriteVarArgFunction(F)});
            changed = true;
        }

        // ============ 第二阶段：调用点改写（caller 级共享缓冲区）============
        // 关键：同一 caller 的所有调用点（>5 参数 + 变参混合）共用入口块一块缓冲区。
        // 每个调用点在发起 call 前从偏移 0 完整覆写，call 返回后即不再使用，窗口互不
        // 重叠（BPF 同步执行；递归因每帧独立栈帧而安全）。这样把"每调用点独立 alloca"
        // 导致的 BPF 后端栈大小累加膨胀（后端不做栈槽复用）压缩为每 caller 单个 alloca。
        //
        // 先按 caller 聚合所有调用点，算出每个 caller 的最大打包字节数；再为每 caller
        // 分配单块 [MaxBytes x i8]，逐点改写。
        //
        // 注意：即使本 TU 没有 >5 参数的定义或变参定义（work/vaWork 都空），间接调用
        // 点（如通过函数指针发起的 6 参调用）仍需改写——collectIndirectCallSites 独立
        // 扫描整个模块。故第二阶段无条件执行。
        {
            const DataLayout &DL = M.getDataLayout();
            SiteMap byCaller;
            BytesMap maxBytes;

            // >5 参数路径：Threshold = KEEP_REGS（前 4 个走寄存器，第 5 个起打包）
            for (auto &w : work)
                collectCallSites(w.F, w.NewF, KEEP_REGS, DL, byCaller, maxBytes);
            // 变参路径：Threshold = NumNamed（具名参数之后的变参实参打包）
            for (auto &w : vaWork)
                collectCallSites(w.F, w.NewF, w.NewF->arg_size() - 1, DL,
                                 byCaller, maxBytes);
            // 间接调用路径：callee 是函数指针，实参类型全在调用点，无需知道 callee 是谁
            collectIndirectCallSites(M, DL, byCaller, maxBytes);

            for (auto &[Caller, sites] : byCaller) {
                // syscall 6 参路径不需要共享缓冲区（无 pack），单独分流。
                // 其余路径共用入口块单块 [MaxBytes x i8]。
                AllocaInst *SharedBuf = nullptr;
                bool anyPack = false;
                for (PackSite &s : sites)
                    if (!s.IsSyscall) { anyPack = true; break; }
                if (anyPack)
                    SharedBuf = allocSharedPackBuf(Caller, maxBytes[Caller]);
                for (PackSite &s : sites) {
                    if (s.IsSyscall)
                        rewriteCallSiteSyscall6(s.CB, s.Callee);
                    else
                        rewriteCallSitePacked(s.CB, s.Callee, SharedBuf,
                                             s.Threshold);
                }
            }
        }

        // ============ 第三阶段：删除旧函数 ============
        // 直接调用与间接调用（>5 参）已在第二阶段全部迁走。但旧 F 可能仍被【非 CallBase】
        // 引用——最典型的是取地址（store ptr @f 到函数指针、函数指针表）。把这类残留 use
        // 重定向到 NewF 的 bitcast：
        //   - 使 IR 合法（旧 F 不再被引用，可安全删除），避免 clang 在后续 instcombine
        //     访问悬空指针而段错误（这是修复前的 P0 崩溃 bug）；
        //   - 让取地址得到的指针指向 NewF，这样后续间接调用（已在第二阶段改写为 5 参 +
        //     pack）能正确命中 NewF 的新 ABI。
        // 取地址本身（如赋值给函数指针变量、存入函数指针表）是合法且被支持的；本 pass
        // 已把通过该指针发起的 >5 参间接调用改写成新 ABI。此处告警仅为提示"发生了重定向"。
        auto rewriteStrayUses = [](Function *OldF, Function *NewF, const char *tag) {
            if (OldF->use_empty())
                return;
            errs() << "BpfWideArgs: note: " << NewF->getName()
                   << " had " << tag
                   << " uses (address-taken); redirected them to the rewritten "
                      "symbol (indirect calls are auto-rewritten to the new ABI)\n";
            PointerType *OldPtrTy = OldF->getType();
            Constant *Alias = ConstantExpr::getBitCast(NewF, OldPtrTy);
            OldF->replaceAllUsesWith(Alias);
        };
        for (auto &w : work) {
            rewriteStrayUses(w.F, w.NewF, "direct-arg");
            w.F->eraseFromParent();
        }
        for (auto &w : vaWork) {
            rewriteStrayUses(w.F, w.NewF, "vararg");
            w.F->eraseFromParent();
        }

        // ---- 全局 va intrinsic lowering ----
        // 非变参函数（如 vfprintf，接收 va_list 参数）体内也可能有 va_copy/va_arg/
        // va_end。这些函数不是变参，BPF 后端不会因 isVarArg 报错，但残留的 va intrinsic
        // 会让 ISel 报 "Cannot select: vastart/vacopy"。
        // 遍历模块所有函数（含上面改写出的 NewF，对它们是幂等的），统一 lower。
        for (Function &F : M) {
            if (F.isDeclaration() || isInternalOrIntrinsic(F))
                continue;
            // VaBase=null：非变参函数里不会有 va_start（clang 不生成），只处理其余三种。
            changed |= lowerVaIntrinsics(F, nullptr);
        }

        return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    // 让 pass 在 -O0 也能跑（不要求优化管道触发）
    static bool isRequired() { return true; }
};

// ===========================================================================
// B. VLA / 动态 alloca 改写
//
// 背景：BPF 后端在 ISel 阶段拒绝动态栈分配（"unsupported dynamic stack
// allocation"），因此 C 的 VLA（`int buf[n];`）与 `__builtin_alloca(n)` 都无法
// 编译。本 pass 在 IR 层把这类动态分配改写成对 BPF_SYS_ALLOCA syscall 的调用。
//
// 改写目标：clang 前端把 VLA 编码为三件套——
//   %sp = call ptr @llvm.stacksave()         ; 记录当前栈顶（退出时回退的 token）
//   %buf = alloca i32, i64 %n                ; 动态分配（被后端拒绝）
//   call void @llvm.stackrestore(ptr %sp)    ; 退回 %sp，释放期间的 alloca
// 其中动态 `alloca` 的总字节数 = 元素数 × 元素大小。
//
// alloca(inc) 语义（VM 内部 syscall，接口形状参考 sbrk：带符号 inc）：inc > 0
// 扩展 / = 0 读当前下界 / < 0 收缩；返回调整后的下界（= 新块起始地址）。本 pass
// 把三件套映射如下：
//   1. 动态 `alloca Ty, i64 %n`
//      以及"固定大小但不在入口块"的 alloca（BPF 同样拒绝后者——优化器有时把
//      编译期已知大小的 VLA 折叠成固定 alloca 但留在循环/中间块里）：
//        → %bytes = ((n * sizeof(Ty)) + 15) & ~15   ; 客户端按 16 字节对齐
//          %p    = call ptr (i64) inttoptr(BPF_CALL_ALLOCA to ptr)(i64 %bytes)
//        inc > 0 时返回值即新块起始地址（C alloca 语义）。
//   2. @llvm.stacksave → alloca(0)：
//        返回当前下界作为 token（inttoptr 到 ptr 以匹配 stacksave 的返回类型）。
//   3. @llvm.stackrestore(tok) → alloca(tok - alloca(0))：
//        先读当前下界，与 token 的差作为收缩量（负值）。clang 在每个 VLA 块的
//        所有退出点（含 break/continue/return/goto）都放了一个 stackrestore，
//        逐个替换即可，无需做控制流分析。
//
// 调用约定：BPF syscall 走 src_reg=0 的 call 指令，imm 直接是 BPF_CALL_* 值。
//   `call ptr inttoptr(i64 <CALL> to ptr)(...)` 经后端 lowering 成一条
//   `call <imm>`（与 musl syscall_arch.h 把 call id 当函数指针直接调用同机制，
//   见 BpfSoftFp.cpp 的同类 inttoptr-callee 用法）。入参落 r1，结果回 r0——无需
//   改 linker、无需符号重写。
//
// 时机：作为模块级 pass 跑在优化器末尾（OptimizerLastEP）。理由：
//   - 必须在 SROA/instcombine 之后，让固定大小的 alloca 先被消除（它们不应被
//     改写，BPF 后端能处理固定 alloca）；只留下真正的动态 alloca。
//   - 必须在 CodeGen 之前（否则后端拒绝动态 alloca）。
//   - 与同 .so 内的 BpfWideArgsPass（PipelineStartEP）无数据依赖：后者只处理
//     CallBase/sret/va intrinsic，不碰 alloca 与 stacksave/stackrestore。
// ===========================================================================

// 构造一次 BPF syscall 调用：call <ptr> inttoptr(i64 <CallId> to ptr)(Args...)。
// 返回值类型按 RetTy 处理（BPF syscall 结果在 r0，整数/指针皆为 i64）。
static Value *emitVlaSyscall(IRBuilder<> &B, LLVMContext &Ctx, uint64_t CallId,
                             ArrayRef<Value *> Args, Type *RetTy) {
    Type *I64Ty = Type::getInt64Ty(Ctx);
    // LLVM 15+ 默认 opaque pointer，函数指针类型即 ptr（地址空间 0）。
    Type *PtrTy = PointerType::get(Ctx, 0);

    // 入参全部 zext 到 i64（BPF 寄存器 64 位；指针/size_t 即 i64）。
    SmallVector<Value *, 4> I64Args;
    for(Value *A : Args) {
        if(A->getType()->isIntegerTy() && A->getType()->getIntegerBitWidth() < 64)
            A = B.CreateZExt(A, I64Ty);
        I64Args.push_back(A);
    }

    // 函数类型：RetTy(I64...)。统一用 i64 入参；返回值用 RetTy（i64 或 ptr）。
    SmallVector<Type *, 4> ArgTys(I64Args.size(), I64Ty);
    Type *EffRetTy = RetTy->isPointerTy() ? I64Ty : RetTy;
    FunctionType *FTy = FunctionType::get(EffRetTy, ArgTys, false);

    // inttoptr(const CallId) 当作函数指针直接调用 → 后端 emit `call <imm>`。
    Value *FnPtr = B.CreateIntToPtr(ConstantInt::get(I64Ty, CallId), PtrTy);
    Value *Call = B.CreateCall(FTy, FnPtr, I64Args);

    // 指针类型结果：i64 → ptr（inttoptr）。整数窄类型：trunc。
    if(RetTy->isPointerTy())
        return B.CreateIntToPtr(Call, RetTy);
    if(RetTy->isIntegerTy() && RetTy->getIntegerBitWidth() < 64)
        return B.CreateTrunc(Call, RetTy);
    return Call;
}

// 处理单个函数：扫描所有动态 alloca 与 stacksave/stackrestore intrinsic，改写之。
static bool rewriteVla(Function &F) {
    LLVMContext &Ctx = F.getContext();
    Type *I64Ty = Type::getInt64Ty(Ctx);
    bool Changed = false;
    SmallVector<Instruction *, 16> ToErase;

    // 第一遍：改写动态 alloca + 非入口块的固定大小 alloca。
    //
    // BPF 后端拒绝两种情况：
    //   (a) 动态大小 alloca（"unsupported dynamic stack allocation"）；
    //   (b) 不在入口块的固定大小 alloca —— 即使大小固定，BPF 也要求所有 alloca
    //       集中在函数入口块（static alloca）。优化器有时会把 VLA（编译期已知大小）
    //       折叠成固定大小 alloca 但仍留在循环/中间块里（典型场景：VLA 指针逃逸到
    //       未内联的函数，阻止了提升），后端照样拒绝。
    //
    // 策略：凡"非常量大小"或"不在入口块"的 alloca，统一改写成 BPF_SYS_ALLOCA
    // syscall（inc = 字节数，inc > 0 时返回新下界 = 新块起始地址）。
    // 入口块里的常量大小 alloca（标准 static alloca）BPF 能处理，不动。
    BasicBlock *Entry = &F.getEntryBlock();
    for(BasicBlock &BB : F) {
        for(Instruction &I : BB) {
            AllocaInst *AI = dyn_cast<AllocaInst>(&I);
            if(!AI) continue;

            Value *ArraySize = AI->getArraySize();
            bool isDynamicSize = ArraySize && !isa<ConstantInt>(ArraySize);
            bool isStaticInEntry = (&BB == Entry) && !isDynamicSize;
            if(isStaticInEntry) continue;  // 标准 static alloca，BPF 接受

            // 总字节数 = 元素数 × 元素大小，统一 i64。
            //   动态：用 ArraySize（非常量）乘以元素大小。
            //   固定但非入口块：用常量元素数（ArraySize==nullptr→1，或 ConstantInt）
            //     乘以元素大小，得一个常量字节数。
            IRBuilder<> B(AI);
            Type *ElemTy = AI->getAllocatedType();
            const DataLayout &DL = F.getParent()->getDataLayout();
            uint64_t ElemSize = DL.getTypeAllocSize(ElemTy);
            Value *Count;
            if(!ArraySize)
                Count = ConstantInt::get(I64Ty, 1);
            else
                Count = B.CreateZExt(ArraySize, I64Ty);
            Value *Bytes = Count;
            if(ElemSize != 1) {
                Value *SizeVal = ConstantInt::get(I64Ty, ElemSize);
                Bytes = B.CreateMul(Bytes, SizeVal, "vla.bytes");
            }
            // 字节数向上取整到 16 的倍数：保证相邻 alloca 块间隔 16 字节、每块起始
            // 相对 r10 偏移 16 对齐。
            //   bytes = (bytes + 15) & ~15
            Constant *Fifteen = ConstantInt::get(I64Ty, 15);
            Constant *InvMask = ConstantInt::get(I64Ty, ~(uint64_t)15);
            Bytes = B.CreateAnd(B.CreateAdd(Bytes, Fifteen), InvMask,
                                "vla.aligned");

            // inc = bytes > 0；新下界即新块起始地址（C alloca 语义）。
            Value *Ptr = emitVlaSyscall(B, Ctx, BPF_CALL_ALLOCA, {Bytes},
                                        AI->getType());
            AI->replaceAllUsesWith(Ptr);
            ToErase.push_back(AI);
            Changed = true;
        }
    }

    // 第二遍：处理 stacksave / stackrestore intrinsic。
    //   stacksave     → alloca(0)：返回当前下界作 token。
    //   stackrestore  → alloca(token - alloca(0))：把下界截回到 token（增量 <= 0）。
    //     clang 在 VLA 块的所有退出点都放了一个 stackrestore，逐个替换即可。
    Constant *Zero = ConstantInt::get(I64Ty, 0);
    for(BasicBlock &BB : F) {
        for(Instruction &I : BB) {
            IntrinsicInst *II = dyn_cast<IntrinsicInst>(&I);
            if(!II) continue;
            Intrinsic::ID ID = II->getIntrinsicID();

            if(ID == Intrinsic::stacksave) {
                // alloca(0) 返回 i64 当前下界，inttoptr 到 ptr 以匹配 stacksave 的
                // 返回类型（emitVlaSyscall 内部完成 inttoptr）。
                IRBuilder<> B(II);
                Value *Tok = emitVlaSyscall(B, Ctx, BPF_CALL_ALLOCA, {Zero},
                                            II->getType());
                II->replaceAllUsesWith(Tok);
                ToErase.push_back(II);
                Changed = true;
            } else if(ID == Intrinsic::stackrestore) {
                // tok_i = ptrtoint(tok, i64)       ; stacksave 时记录的下界
                // cur   = alloca(0)                 ; i64 当前下界
                // inc   = cur - tok_i               ; 通常 < 0（要收缩到 tok 之上）
                // call alloca(inc)                  ; 返回值丢弃
                //
                // 推导：栈向低地址生长，下界 = r10 - total_len。stacksave 时 tok 较高
                // （total_len 小）；本次 stackrestore 时 cur 较低（期间做过 alloca，
                // total_len 大）。要截回到 tok，alloca_len 减少量 = (cur_total -
                // save_total) > 0；alloca 的 inc 是 alloca_len 增量，所以 inc < 0。
                // 用地址表达：inc = cur_lower - tok = (r10 - cur_total) -
                // (r10 - save_total) = save_total - cur_total < 0 ✓
                //
                // 注意：这里未对 inc 做夹紧（理论上 clang 生成的 stackrestore 总满足
                // cur >= tok 即 inc <= 0）。若 inc > 0，stackrestore 会反向扩展 alloca
                // 区而非收缩——当前实现不设护栏，依赖前端正确性。
                IRBuilder<> B(II);
                Value *TokPtr = II->getArgOperand(0);
                Value *TokI = B.CreatePtrToInt(TokPtr, I64Ty, "alloca.tok");
                Value *Cur  = emitVlaSyscall(B, Ctx, BPF_CALL_ALLOCA, {Zero}, I64Ty);
                Value *Inc  = B.CreateSub(Cur, TokI, "alloca.inc");
                emitVlaSyscall(B, Ctx, BPF_CALL_ALLOCA, {Inc}, I64Ty);
                II->replaceAllUsesWith(UndefValue::get(I.getType()));
                ToErase.push_back(II);
                Changed = true;
            }
        }
    }

    for(Instruction *I : ToErase)
        I->eraseFromParent();

    return Changed;
}

class BpfVlaPass : public PassInfoMixin<BpfVlaPass> {
public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        if(F.isDeclaration())
            return PreservedAnalyses::all();
        return rewriteVla(F) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

// C. by-value 非平凡析构参数（unique_ptr 8B / shared_ptr 16B 等）double-free 修复
//    （上游 LLVM #207686）。两个 EP 都跑：
//   - PipelineStartEP（紧跟 BpfWideArgsPass）：在 -O1 之前清零备份临时。若晚于此，
//     -O1 会把备份临时与源对象 fold（误以为两者共享同一资源），把 caller 结尾的
//     析构直接 fold 成对原 ctrl 的 atomicrmw -1（miscompile 形态）。
//   - OptimizerLastEP：兜底 -O1 已把 move-construct inline 成 store、无 call 形式
//     move-ctor 可识别的场景（unique_ptr 经此路径）。
class BpfByvalTmpPass : public PassInfoMixin<BpfByvalTmpPass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        return eliminateByvalScalarTemporaries(M)
                   ? PreservedAnalyses::none()
                   : PreservedAnalyses::all();
    }
    static bool isRequired() { return true; }
};

// D. atomic load/store 降级（解锁 iostream/locale.cpp 等的 static guard）。
//
// 背景：eBPF 指令集（含 v4）只有 RMW 类原子指令（atomic_add/or/and/xor、xchg、
// cmpxchg，全部 SEQ_CST），【没有】独立的 plain atomic load / atomic store 指令。
// 因此 clang 的 BPF 后端对 IR 里的 `load atomic`/`store atomic` 报
//   "Cannot select: ... AtomicLoad<... acquire ...>"
// （AtomicRMW/AtomicCmpXchg 则能正常 select 成 BPF_ATOMIC 指令）。
// 这一缺口直到 LLVM 21 才由新的 BPF_LOAD_ACQ(imm=0x100)/BPF_STORE_REL(imm=0x110)
// 指令补上；本项目当前用 LLVM 19，且即便升级到 21 也需要 VM 侧识别这两个 imm。
//
// 阻塞场景：C++ 函数内 `static T x = init();` 的初始化 guard。clang IRGen 生成
// fast-path 优化——先 `load atomic i8 acquire`（读 guard flag），非 0 直接返回，
// 为 0 才走 slow path `call __cxa_guard_acquire`。locale.cpp/ios.cpp/iostream.cpp
// 大量用 static 局部变量（locale::id、iostream Init 的 `static bool once` 等），
// 全部撞上这个缺口。
//
// 为何降级（而非用 xchg/cmpxchg 模拟）是正确的：
// 1) eBPF ISA 在 LLVM 19 下根本没有 plain atomic load 指令，物理上无法保留
//    "原子 load" 语义；这是 target 约束，不是 VM 实现缺口（bpfvm 的 do_atomic
//    完整支持 RMW/xchg/cmpxchg，见 insn.cpp）。
// 2) guard 的 fast-path load 后紧跟的 __cxa_guard_acquire 在本项目的 cxxabi_stub
//    里【本就是非原子实现】（cxxabi_stub.cpp："简化：不做线程安全
//    （_LIBCPP_HAS_NO_THREADS）"）。整个 guard 机制在 _LIBCPP_HAS_NO_THREADS 下
//    不保证多线程安全，fast-path 那一处原子是孤立的、无意义的。降级它不削弱任何
//    现有语义——项目当前的语义就是单线程 guard。
// 3) store atomic 理论上可用 eBPF xchg 实现（保留 SEQ_CST store 语义），但与
//    load 配对时仍无法让 load 端原子，且 guard 的 store（__cxa_guard_release
//    指向的 guard 字节写入）同样位于非原子的 slow path 之后。统一降级最简单一致。
//
// 范围：
//   D1: LoadInst/StoreInst 的 atomic 形式 → 降级为普通 load/store（见上）。
//   D2: i8/i16 的 AtomicRMW/AtomicCmpXchg → 展开成对包含它的对齐 i32 槽的子字节 CAS
//       循环（BPF 后端只支持 i32/i64 的 RMW/cmpxchg，窄类型会报 "unsupported atomic
//       operation, please use 32/64 bit version"）。照搬 LLVM 官方 expandPartwordCmpXchg
//       /expandPartwordAtomicRMW 算法（llvm/lib/CodeGen/AtomicExpandPass.cpp），展开后
//       生成普通 i32 atomic，VM 的 do_atomic 原生支持（BPF_W），无需改 VM。
//       解锁 atomic<bool>/char/short 等标准 C++ 写法。
//   i32/i64 的 RMW/cmpxchg 不动（后端原生支持）。
//
// 时机：OptimizerLastEPCallback（晚跑，与 VLA/ByvalTmp 同列）。晚跑能让优化器
// 先尝试消除可证明为单线程的 atomic（部分 guard 在 -O1 inline 后会被删），
// 只改写真正漏到后端的。isRequired()=true 保证 -O0 也跑。
// 顺序：D2 先于 D1——D2 展开会插入普通（非原子）load，不该被 D1 再降级。
class BpfAtomicLowerPass : public PassInfoMixin<BpfAtomicLowerPass> {
    // 子字节 CAS 的 mask/shift 计算结果（对应 LLVM PartwordMaskValues）。
    struct PartwordMaskValues {
        Type *WordType = nullptr;        // 展开后的宽类型（i32）
        Value *AlignedAddr = nullptr;    // 对齐到 WordSize 的地址（addr & ~(WS-1)）
        Align AlignedAddrAlignment;      // 对齐值（= WordSize）
        Value *ShiftAmt = nullptr;       // 目标字节的位偏移（PtrLSB * 8）
        Value *Mask = nullptr;           // 目标字节在宽槽里的位掩码
        Value *Inv_Mask = nullptr;       // 反掩码（清目标字节用）
    };

    static constexpr unsigned MinWordSize = 4;  // BPF 原子最小宽度（i32）

    // 窄原子子字节 CAS 的前提：对象位于一个可安全 4 字节读写的槽内（AlignedAddr 处
    // 的 i32 load/store 不能越界破坏相邻对象）。对 _Atomic 全局/堆对象成立（标准要求
    // 对齐）；但栈上窄 atomic（如局部 uint16_t）clang 只给 align=2 的 alloca，&s & ~3
    // 会越过对象边界读到/写脏相邻栈数据。
    // 修复：把窄 atomic 指针背后的 alloca 对齐提升到 MinWordSize。提升后编译器给它
    // 分配 4 字节对齐的栈槽，&s & 3 == 0，shift=0，CAS 只在对象自身的 4 字节内（对象
    // 因 alloca 变大而获得额外 padding，不越界）。对非 alloca（堆/全局/参数）不动——
    // 它们的对齐由分配方保证，且 _Atomic 语义要求对象布局容纳原子访问。
    static void widenUnderlyingAllocaAlign(Value *Addr) {
        // 剥掉 bitcast / GEP（零偏移），找到底层 alloca。
        Value *U = Addr->stripPointerCasts();
        // 只处理「整个 alloca 的起始」（GEP 带偏移的不安全，无法靠提升对齐修复）。
        if(auto *AI = dyn_cast<AllocaInst>(U)) {
            if(AI->getAlign().value() < MinWordSize)
                AI->setAlignment(Align(MinWordSize));
        }
    }

    // 计算 addr/shift/mask（照搬 LLVM createMaskInstrs，简化：只处理整数小端）。
    static PartwordMaskValues createMaskInstrs(IRBuilder<> &Builder, Instruction *I,
                                                Type *ValueType, Value *Addr,
                                                Align AddrAlign) {
        PartwordMaskValues PMV;
        const DataLayout &DL = I->getModule()->getDataLayout();
        LLVMContext &Ctx = I->getContext();
        unsigned ValueSize = DL.getTypeStoreSize(ValueType);  // i8→1, i16→2
        PMV.WordType = Type::getInt32Ty(Ctx);
        PMV.AlignedAddrAlignment = Align(MinWordSize);

        PointerType *PtrTy = cast<PointerType>(Addr->getType());
        IntegerType *IntTy = DL.getIndexType(Ctx, PtrTy->getAddressSpace());
        Value *PtrLSB;
        if(AddrAlign < MinWordSize) {
            // 地址对齐不足：运行时对齐（ptrmask）+ 取低位算 shift。
            PMV.AlignedAddr = Builder.CreateIntrinsic(
                Intrinsic::ptrmask, {PtrTy, IntTy},
                {Addr, ConstantInt::get(IntTy, ~(uint64_t)(MinWordSize - 1))}, nullptr,
                "AlignedAddr");
            Value *AddrInt = Builder.CreatePtrToInt(Addr, IntTy);
            PtrLSB = Builder.CreateAnd(AddrInt, MinWordSize - 1, "PtrLSB");
        } else {
            // 已对齐：LSB 已知 0，shift=0。
            PMV.AlignedAddr = Addr;
            PtrLSB = ConstantInt::getNullValue(IntTy);
        }
        PMV.ShiftAmt = Builder.CreateTrunc(Builder.CreateShl(PtrLSB, 3), PMV.WordType,
                                            "ShiftAmt");
        PMV.Mask = Builder.CreateShl(
            ConstantInt::get(PMV.WordType, (1 << (ValueSize * 8)) - 1), PMV.ShiftAmt,
            "Mask");
        PMV.Inv_Mask = Builder.CreateNot(PMV.Mask, "Inv_Mask");
        return PMV;
    }

    // 从宽槽里提取目标窄值（lshr + trunc）。
    static Value *extractMaskedValue(IRBuilder<> &Builder, Value *WideWord, Type *ValueType,
                                      const PartwordMaskValues &PMV) {
        Value *Shift = Builder.CreateLShr(WideWord, PMV.ShiftAmt, "shifted");
        return Builder.CreateTrunc(Shift, ValueType, "extracted");
    }

    // D2a: i8/i16 cmpxchg → i32 子字节 CAS loop（照搬 expandPartwordCmpXchg）。
    // IR 序列见 llvm/lib/CodeGen/AtomicExpandPass.cpp:1015 注释。
    static bool expandPartwordCmpXchg(AtomicCmpXchgInst *CI) {
        Value *Addr = CI->getPointerOperand();
        widenUnderlyingAllocaAlign(Addr);  // 提升栈窄 atomic 的对齐，避免越界
        Value *Cmp = CI->getCompareOperand();
        Value *NewVal = CI->getNewValOperand();
        Type *ValueType = Cmp->getType();

        BasicBlock *BB = CI->getParent();
        Function *F = BB->getParent();
        IRBuilder<> Builder(CI);
        BasicBlock *EndBB = BB->splitBasicBlock(CI->getIterator(), "partword.cmpxchg.end");
        BasicBlock *FailureBB = BasicBlock::Create(CI->getContext(),
                                                    "partword.cmpxchg.failure", F, EndBB);
        BasicBlock *LoopBB = BasicBlock::Create(CI->getContext(),
                                                 "partword.cmpxchg.loop", F, FailureBB);
        std::prev(BB->end())->eraseFromParent();  // 去掉 split 加的错分支
        Builder.SetInsertPoint(BB);

        PartwordMaskValues PMV = createMaskInstrs(Builder, CI, ValueType, Addr, CI->getAlign());
        Value *NewVal_Shifted = Builder.CreateShl(Builder.CreateZExt(NewVal, PMV.WordType),
                                                   PMV.ShiftAmt);
        Value *Cmp_Shifted = Builder.CreateShl(Builder.CreateZExt(Cmp, PMV.WordType),
                                                PMV.ShiftAmt);
        LoadInst *InitLoaded = Builder.CreateLoad(PMV.WordType, PMV.AlignedAddr);
        InitLoaded->setVolatile(CI->isVolatile());
        Value *InitLoaded_MaskOut = Builder.CreateAnd(InitLoaded, PMV.Inv_Mask);
        Builder.CreateBr(LoopBB);

        // loop:
        Builder.SetInsertPoint(LoopBB);
        PHINode *Loaded_MaskOut = Builder.CreatePHI(PMV.WordType, 2);
        Loaded_MaskOut->addIncoming(InitLoaded_MaskOut, BB);
        Value *FullWord_NewVal = Builder.CreateOr(Loaded_MaskOut, NewVal_Shifted);
        Value *FullWord_Cmp = Builder.CreateOr(Loaded_MaskOut, Cmp_Shifted);
        AtomicCmpXchgInst *NewCI = Builder.CreateAtomicCmpXchg(
            PMV.AlignedAddr, FullWord_Cmp, FullWord_NewVal, PMV.AlignedAddrAlignment,
            CI->getSuccessOrdering(), CI->getFailureOrdering(), CI->getSyncScopeID());
        NewCI->setVolatile(CI->isVolatile());
        NewCI->setWeak(CI->isWeak());
        Value *OldVal = Builder.CreateExtractValue(NewCI, 0);
        Value *Success = Builder.CreateExtractValue(NewCI, 1);
        if(CI->isWeak())
            Builder.CreateBr(EndBB);
        else
            Builder.CreateCondBr(Success, EndBB, FailureBB);

        // failure: 周边位变了才重试，否则真实失败。
        Builder.SetInsertPoint(FailureBB);
        Value *OldVal_MaskOut = Builder.CreateAnd(OldVal, PMV.Inv_Mask);
        Value *ShouldContinue = Builder.CreateICmpNE(Loaded_MaskOut, OldVal_MaskOut);
        Builder.CreateCondBr(ShouldContinue, LoopBB, EndBB);
        Loaded_MaskOut->addIncoming(OldVal_MaskOut, FailureBB);

        // end: 提取旧值，重组 {窄值, i1} 返回。
        Builder.SetInsertPoint(CI);
        Value *FinalOldVal = extractMaskedValue(Builder, OldVal, ValueType, PMV);
        Value *Res = PoisonValue::get(CI->getType());
        Res = Builder.CreateInsertValue(Res, FinalOldVal, 0);
        Res = Builder.CreateInsertValue(Res, Success, 1);
        CI->replaceAllUsesWith(Res);
        CI->eraseFromParent();
        return true;
    }

    // 算 RMW 在【窄值原宽】下的 new value（Min/Max 等需原宽比较）。
    static Value *buildRMWValue(AtomicRMWInst::BinOp Op, IRBuilder<> &B,
                                 Value *Loaded, Value *Inc) {
        switch(Op) {
        case AtomicRMWInst::Xchg: return Inc;
        case AtomicRMWInst::Add:  return B.CreateAdd(Loaded, Inc, "new");
        case AtomicRMWInst::Sub:  return B.CreateSub(Loaded, Inc, "new");
        case AtomicRMWInst::And:  return B.CreateAnd(Loaded, Inc, "new");
        case AtomicRMWInst::Nand: return B.CreateNot(B.CreateAnd(Loaded, Inc), "new");
        case AtomicRMWInst::Or:   return B.CreateOr(Loaded, Inc, "new");
        case AtomicRMWInst::Xor:  return B.CreateXor(Loaded, Inc, "new");
        case AtomicRMWInst::Max:  return B.CreateSelect(B.CreateICmpSGT(Loaded, Inc), Loaded, Inc, "new");
        case AtomicRMWInst::Min:  return B.CreateSelect(B.CreateICmpSLE(Loaded, Inc), Loaded, Inc, "new");
        case AtomicRMWInst::UMax: return B.CreateSelect(B.CreateICmpUGT(Loaded, Inc), Loaded, Inc, "new");
        case AtomicRMWInst::UMin: return B.CreateSelect(B.CreateICmpULE(Loaded, Inc), Loaded, Inc, "new");
        default: return nullptr;  // FP/UIncWrap/UDecWrap 不处理（窄场景无意义）
        }
    }

    // D2b: i8/i16 atomicrmw → i32 子字节 CAS loop（照搬 expandPartwordAtomicRMW）。
    // Or/Xor/And 直接 widen 成 i32 原子位运算（周边位为 0/1 不影响结果；And 需把
    //   非目标字节置 1 避免清掉）。Add/Sub/Nand 在移位后的位上算再 mask 回目标字节。
    //   Min/Max/UMin/UMax extract 出窄值原宽算再 insert 回宽槽。
    static bool expandPartwordRMW(AtomicRMWInst *AI) {
        AtomicRMWInst::BinOp Op = AI->getOperation();
        Type *ValueType = AI->getType();
        Value *Addr = AI->getPointerOperand();
        widenUnderlyingAllocaAlign(Addr);  // 提升栈窄 atomic 的对齐，避免越界
        AtomicOrdering MemOpOrder = AI->getOrdering();
        SyncScope::ID SSID = AI->getSyncScopeID();
        IRBuilder<> Builder(AI);

        PartwordMaskValues PMV = createMaskInstrs(Builder, AI, ValueType, Addr, AI->getAlign());

        // 分支 1: Or/Xor/And widen 成 i32 原子位运算（不需 CAS loop）。
        if(Op == AtomicRMWInst::Or || Op == AtomicRMWInst::Xor || Op == AtomicRMWInst::And) {
            Value *ValOperand_Shifted = Builder.CreateShl(
                Builder.CreateZExt(AI->getValOperand(), PMV.WordType), PMV.ShiftAmt,
                "ValOperand_Shifted");
            Value *NewOperand = (Op == AtomicRMWInst::And)
                                    ? Builder.CreateOr(ValOperand_Shifted, PMV.Inv_Mask, "AndOperand")
                                    : ValOperand_Shifted;
            AtomicRMWInst *NewAI = Builder.CreateAtomicRMW(Op, PMV.AlignedAddr, NewOperand,
                                                            PMV.AlignedAddrAlignment, MemOpOrder, SSID);
            Value *FinalOld = extractMaskedValue(Builder, NewAI, ValueType, PMV);
            AI->replaceAllUsesWith(FinalOld);
            AI->eraseFromParent();
            return true;
        }

        // 分支 2/3: CAS loop（在移位后的位上算，或 extract 后原宽算）。
        // 预计算移位后的 incr（Add/Sub/Nand/Xchg 用；Min/Max 等用原宽 Inc）。
        Value *ValOperand_Shifted = nullptr;
        if(Op == AtomicRMWInst::Xchg || Op == AtomicRMWInst::Add ||
           Op == AtomicRMWInst::Sub || Op == AtomicRMWInst::Nand) {
            ValOperand_Shifted = Builder.CreateShl(
                Builder.CreateZExt(AI->getValOperand(), PMV.WordType), PMV.ShiftAmt,
                "ValOperand_Shifted");
        }

        // PerformOp: 给定当前宽槽值 Loaded，算要 CAS 进去的 FullWord。
        auto PerformOp = [&](IRBuilder<> &B, Value *Loaded) -> Value * {
            switch(Op) {
            case AtomicRMWInst::Xchg: {
                Value *Loaded_MaskOut = B.CreateAnd(Loaded, PMV.Inv_Mask);
                return B.CreateOr(Loaded_MaskOut, ValOperand_Shifted);
            }
            case AtomicRMWInst::Add:
            case AtomicRMWInst::Sub:
            case AtomicRMWInst::Nand: {
                Value *NewVal = buildRMWValue(Op, B, Loaded, ValOperand_Shifted);
                Value *NewVal_Masked = B.CreateAnd(NewVal, PMV.Mask);
                Value *Loaded_MaskOut = B.CreateAnd(Loaded, PMV.Inv_Mask);
                return B.CreateOr(Loaded_MaskOut, NewVal_Masked);
            }
            case AtomicRMWInst::Max: case AtomicRMWInst::Min:
            case AtomicRMWInst::UMax: case AtomicRMWInst::UMin: {
                Value *Loaded_Extract = extractMaskedValue(B, Loaded, ValueType, PMV);
                Value *NewVal = buildRMWValue(Op, B, Loaded_Extract, AI->getValOperand());
                if(!NewVal) return nullptr;
                Value *ZExt = B.CreateZExt(NewVal, PMV.WordType, "extended");
                Value *Shift = B.CreateShl(ZExt, PMV.ShiftAmt, "shifted", /*HasNUW*/ true);
                Value *And = B.CreateAnd(Loaded, PMV.Inv_Mask, "unmasked");
                return B.CreateOr(And, Shift, "inserted");
            }
            default:
                return nullptr;
            }
        };

        // 构造 CAS loop（照搬 insertRMWCmpXchgLoop）。
        BasicBlock *BB = Builder.GetInsertBlock();
        Function *F = BB->getParent();
        BasicBlock *ExitBB = BB->splitBasicBlock(Builder.GetInsertPoint(), "atomicrmw.end");
        BasicBlock *LoopBB = BasicBlock::Create(AI->getContext(), "atomicrmw.start", F, ExitBB);
        std::prev(BB->end())->eraseFromParent();
        Builder.SetInsertPoint(BB);
        LoadInst *InitLoaded = Builder.CreateLoad(PMV.WordType, PMV.AlignedAddr);
        Builder.CreateBr(LoopBB);

        Builder.SetInsertPoint(LoopBB);
        PHINode *Loaded = Builder.CreatePHI(PMV.WordType, 2, "loaded");
        Loaded->addIncoming(InitLoaded, BB);
        Value *NewVal = PerformOp(Builder, Loaded);
        AtomicOrdering CmpOrder = (MemOpOrder == AtomicOrdering::Unordered)
                                      ? AtomicOrdering::Monotonic : MemOpOrder;
        AtomicCmpXchgInst *Pair = Builder.CreateAtomicCmpXchg(
            PMV.AlignedAddr, Loaded, NewVal, PMV.AlignedAddrAlignment, CmpOrder,
            AtomicCmpXchgInst::getStrongestFailureOrdering(CmpOrder), SSID);
        Value *NewLoaded = Builder.CreateExtractValue(Pair, 0);
        Value *Success = Builder.CreateExtractValue(Pair, 1);
        Loaded->addIncoming(NewLoaded, LoopBB);
        Builder.CreateCondBr(Success, ExitBB, LoopBB);

        Builder.SetInsertPoint(ExitBB, ExitBB->begin());
        Value *FinalOld = extractMaskedValue(Builder, NewLoaded, ValueType, PMV);
        AI->replaceAllUsesWith(FinalOld);
        AI->eraseFromParent();
        return true;
    }

public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        if(F.isDeclaration())
            return PreservedAnalyses::all();

        bool Changed = false;
        SmallVector<LoadInst *, 16> Loads;
        SmallVector<StoreInst *, 16> Stores;
        SmallVector<AtomicCmpXchgInst *, 16> NarrowCmpXchgs;
        SmallVector<AtomicRMWInst *, 16> NarrowRMWs;
        for(BasicBlock &BB : F) {
            for(Instruction &I : BB) {
                if(auto *LI = dyn_cast<LoadInst>(&I)) {
                    if(LI->isAtomic())
                        Loads.push_back(LI);
                } else if(auto *SI = dyn_cast<StoreInst>(&I)) {
                    if(SI->isAtomic())
                        Stores.push_back(SI);
                } else if(auto *CmpX = dyn_cast<AtomicCmpXchgInst>(&I)) {
                    // 窄 cmpxchg（i8/i16）：BPF 后端只支持 i32/i64，需展开。
                    if(CmpX->getCompareOperand()->getType()->getIntegerBitWidth() < 32)
                        NarrowCmpXchgs.push_back(CmpX);
                } else if(auto *RMW = dyn_cast<AtomicRMWInst>(&I)) {
                    // 窄 RMW：同上。跳过浮点（BPF 无窄浮点原子场景）。
                    if(!RMW->isFloatingPointOperation() &&
                       RMW->getType()->getIntegerBitWidth() < 32)
                        NarrowRMWs.push_back(RMW);
                }
            }
        }

        // D2 先展开窄原子（会插入普通 load，不该被 D1 再降级）。
        for(AtomicCmpXchgInst *CmpX : NarrowCmpXchgs) {
            expandPartwordCmpXchg(CmpX);
            Changed = true;
        }
        for(AtomicRMWInst *RMW : NarrowRMWs) {
            expandPartwordRMW(RMW);
            Changed = true;
        }

        // D1: load atomic T, ptr <order>, align A  →  load T, ptr, align A
        // 直接构造普通 LoadInst（IRBuilder 的 CreateLoad 无带 Align 的重载），
        // 复制对齐/volatile/调试元数据，order 设为 NotAtomic，插在原指令前再替换。
        for(LoadInst *LI : Loads) {
            LoadInst *New = new LoadInst(LI->getType(), LI->getPointerOperand(), "",
                                          LI->isVolatile(), LI->getAlign(),
                                          LI->getIterator());
            New->setOrdering(AtomicOrdering::NotAtomic);
            if(LI->hasMetadata())
                New->setMetadata(LLVMContext::MD_dbg, LI->getMetadata(LLVMContext::MD_dbg));
            LI->replaceAllUsesWith(New);
            LI->eraseFromParent();
            Changed = true;
        }

        // D1: store atomic T v, ptr <order>, align A  →  store T v, ptr, align A
        for(StoreInst *SI : Stores) {
            StoreInst *New = new StoreInst(SI->getValueOperand(), SI->getPointerOperand(),
                                            SI->isVolatile(), SI->getAlign(),
                                            SI->getIterator());
            New->setOrdering(AtomicOrdering::NotAtomic);
            if(SI->hasMetadata())
                New->setMetadata(LLVMContext::MD_dbg, SI->getMetadata(LLVMContext::MD_dbg));
            SI->eraseFromParent();
            Changed = true;
        }

        return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
    static bool isRequired() { return true; }
};

} // namespace

// ---- 插件注册：支持新的 PassBuilder / -fpass-plugin 机制 ----
// 一个 .so 注册多个独立 pass，挂在各自正确的 pipeline EP：
//   - BpfWideArgsPass： PipelineStartEP（早，所有 -O 触发）—— 改签名/调用点。
//   - BpfVlaPass：      OptimizerLastEP（晚）+ -O0 兜底的 PipelineStartEP ——
//                       必须在 SROA/instcombine 之后，只处理漏网的动态 alloca。
//   - BpfByvalTmpPass： PipelineStartEP（早，紧跟 WideArgs）+ OptimizerLastEP（晚兜底）
//                       —— by-value 非平凡析构参数 double-free 修复（≤16B；unique_ptr
//                       8B / shared_ptr 16B），上游 #207686 的本仓库 workaround。
//   - BpfAtomicLowerPass: OptimizerLastEP（晚）—— 把 plain atomic load/store 降级
//                       为普通 load/store（解锁 iostream/static guard；见 pass 注释）。
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "BpfWideArgs", LLVM_VERSION_STRING, [](PassBuilder &PB) {
        // A. BpfWideArgsPass：在模块级别的优化管道起始处插入，保证在 BPF 后端
        // codegen 之前生效。PipelineStartEPCallback 在每一个 -O 级别都会触发。
        PB.registerPipelineStartEPCallback(
            [](ModulePassManager &MPM, OptimizationLevel) {
                MPM.addPass(BpfWideArgsPass());
                // C. by-value 析构参数 double-free 修复（早跑一份，详见 BpfByvalTmpPass
                // 注释）：必须在 -O1 之前清零备份临时，否则 -O1 会把它与源对象 fold，
                // 把 caller 析构直接 fold 成对原 ctrl 的 atomicrmw -1（miscompile）。
                // OptimizerLastEP 还有一份兜底（见下 addByvalTmpPass）。
                MPM.addPass(BpfByvalTmpPass());
            });

        // B. BpfVlaPass：跑在优化器末尾
        //   - 必须在 SROA/instcombine 之后：固定大小 alloca 先被消除/提升，本 pass
        //     只需处理"漏网"的动态 alloca 与被优化器留在非入口块的固定 alloca
        //     （BPF 后端同样拒绝后者）。
        //   - 必须在 CodeGen 之前：否则后端拒绝动态/非入口块 alloca。
        auto addVlaPass = [](ModulePassManager &MPM) {
            FunctionPassManager FPM;
            FPM.addPass(BpfVlaPass());
            MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
        };
        // C. by-value 标量析构参数 double-free 修复：晚跑（见 BpfByvalTmpPass 注释）。
        auto addByvalTmpPass = [](ModulePassManager &MPM) {
            MPM.addPass(BpfByvalTmpPass());
        };
        // D. plain atomic load/store 降级：晚跑（见 BpfAtomicLowerPass 注释），让
        //   优化器先消除可证明单线程的 atomic，只改写漏到后端的。与 B/C 无数据依赖，
        //   挂同一个 OptimizerLastEP（顺序无要求：彼此操作的指令不相交）。
        auto addAtomicLowerPass = [](ModulePassManager &MPM) {
            FunctionPassManager FPM;
            FPM.addPass(BpfAtomicLowerPass());
            MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
        };
        PB.registerOptimizerLastEPCallback(
#if LLVM_VERSION_MAJOR >= 21
            [addVlaPass, addByvalTmpPass, addAtomicLowerPass](ModulePassManager &MPM, OptimizationLevel, ThinOrFullLTOPhase) {
#else
            [addVlaPass, addByvalTmpPass, addAtomicLowerPass](ModulePassManager &MPM, OptimizationLevel) {
#endif
                addVlaPass(MPM);
                addByvalTmpPass(MPM);
                addAtomicLowerPass(MPM);
            });
        // -O0：clang 的 -O0 路径不经过常规 pass 管理器，OptimizerLastEP 实际不触发；
        // 在 PipelineStartEP 显式补一份（仅 O0）。本项目 test/Makefile 与 build_*.sh
        // 均用 -O1 编译，故 -O0 下不支持 VLA（与 BpfSoftFp 同限制）。
        // atomic-lowering 的 isRequired()=true，常规管道必跑；这里同样给 -O0 补一份。
        // 本回调晚于上方 A（WideArgs）的 PipelineStartEP 回调注册。
        PB.registerPipelineStartEPCallback(
            [addVlaPass, addAtomicLowerPass](ModulePassManager &MPM, OptimizationLevel OL) {
                if(OL == OptimizationLevel::O0) {
                    addVlaPass(MPM);
                    addAtomicLowerPass(MPM);
                }
            });
    }};
}
