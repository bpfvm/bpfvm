//===- BpfWideArgs.cpp - Pass: BPF 参数/变参/struct 返回支持 ---------------===//
//
// 一个 LLVM ModulePass 插件，解决 BPF 后端的三类调用约定限制：
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
// 用法：clang -target bpf -fpass-plugin=libBpfWideArgs.so ...
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/DenseMap.h"
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

        // 第 0 遍：剥离 sret，让"返回结构体"的函数能编译。
        // 独立于 >5 参数处理，两者可叠加（sret 指针也算一个参数）。
        changed |= stripSret(M);

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

} // namespace

// ---- 插件注册：支持新的 PassBuilder / -fpass-plugin 机制 ----
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "BpfWideArgs", LLVM_VERSION_STRING, [](PassBuilder &PB) {
        // 在模块级别的优化管道起始处插入，保证在 BPF 后端 codegen 之前生效。
        // PipelineStartEPCallback 在每一个 -O 级别都会触发。
        PB.registerPipelineStartEPCallback(
            [](ModulePassManager &MPM, OptimizationLevel) {
                MPM.addPass(BpfWideArgsPass());
            });
    }};
}
