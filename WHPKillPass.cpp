#include "WHPKillPass.h"

#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/CommandLine.h"

#include <chrono>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

using namespace llvm;

llvm::cl::opt<bool> WHPKillEnable("obfwhpkill", llvm::cl::init(true), llvm::cl::desc("Master Toggle"));

static std::mt19937_64 WhpkillRng((uint64_t)std::random_device{}() ^ (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count());

static constexpr unsigned PerFnCap = 256;
static constexpr unsigned MinBitwidth = 8;
static constexpr unsigned MaxBitwidth = 64;
static constexpr unsigned KusdInterruptTimeOff = 0x008;
static constexpr unsigned KusdBaseLo = 0x7FFE0000u;
static constexpr unsigned KusdBaseHi = 0u;
static constexpr unsigned InterruptSleepMs = 5;

static bool HasAnnotationTag(Function& f, const char* tag)
{
    Module* m = f.getParent();
    GlobalVariable* ga = m->getGlobalVariable("llvm.global.annotations");
    if (!ga) return false;
    ConstantArray* ca = dyn_cast<ConstantArray>(ga->getOperand(0));
    if (!ca) return false;
    for (unsigned i = 0; i < ca->getNumOperands(); ++i)
    {
        ConstantStruct* cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
        if (!cs) continue;
        if (cs->getOperand(0)->stripPointerCasts() != &f) continue;
        auto* strgv = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!strgv || !strgv->hasInitializer()) continue;
        auto* cds = dyn_cast<ConstantDataSequential>(strgv->getInitializer());
        if (!cds || !cds->isString()) continue;
        if (strcmp(cds->getAsString().str().c_str(), tag) == 0) return true;
    }
    return false;
}

static bool HasWHPKillAnnotation(Function& f)
{
    return HasAnnotationTag(f, "whpkill");
}

static bool HasNoWHPKillAnnotation(Function& f)
{
    return HasAnnotationTag(f, "nowhpkill");
}

struct PerFuncSummary
{
    std::string FuncName;
    uint64_t KBase = 0;
    unsigned SignalsEmitted = 0;
    unsigned SitesEmitted = 0;
    unsigned ConstsEncrypted = 0;
    unsigned UsesRewritten = 0;
    unsigned BbsCovered = 0;
    unsigned LoopHdrSkipped = 0;
    unsigned CapHit = 0;
};

static uint64_t Rand64(std::mt19937_64& local)
{
    return local();
}

static Value* EmitCpuid(IRBuilder<>& b, uint32_t leaf, const Twine& nm)
{
    LLVMContext& ctx = b.getContext();
    Type* i32 = Type::getInt32Ty(ctx);
    SmallVector<Type*, 4> tuplefields = {i32, i32, i32, i32};
    StructType* quadty = StructType::get(ctx, tuplefields);
    SmallVector<Type*, 2> asmargtys = {i32, i32};
    FunctionType* asmty = FunctionType::get(quadty, asmargtys, false);

    InlineAsm* ia = InlineAsm::get(asmty, "cpuid", "={ax},={bx},={cx},={dx},0,2,~{dirflag},~{fpsr},~{flags}", true, false, InlineAsm::AD_ATT);
    SmallVector<Value*, 2> asmargs = {ConstantInt::get(i32, leaf), ConstantInt::get(i32, 0u)};
    CallInst* ci = b.CreateCall(ia, asmargs, nm);
    ci->setDoesNotThrow();
    return ci;
}

static Value* EmitEqNormalize(IRBuilder<>& b, Value* d, const Twine& nm)
{
    Type* i64 = Type::getInt64Ty(b.getContext());
    Value* d64 = (d->getType()->isIntegerTy(64)) ? d : b.CreateZExt(d, i64, nm + ".Z");
    Value* neg = b.CreateNeg(d64, nm + ".Neg");
    Value* orc = b.CreateOr(d64, neg, nm + ".Orc");
    Value* nz = b.CreateLShr(orc, ConstantInt::get(i64, 63), nm + ".Nz");
    Value* eq = b.CreateXor(nz, ConstantInt::get(i64, 1), nm + ".Eq");
    return b.CreateNeg(eq, nm + ".Mask");
}

static Value* EmitNzNormalize(IRBuilder<>& b, Value* v, const Twine& nm)
{
    Type* i64 = Type::getInt64Ty(b.getContext());
    Value* v64 = (v->getType()->isIntegerTy(64)) ? v : b.CreateZExt(v, i64, nm + ".Z");
    Value* neg = b.CreateNeg(v64, nm + ".Neg");
    Value* orc = b.CreateOr(v64, neg, nm + ".Orc");
    Value* msb = b.CreateLShr(orc, ConstantInt::get(i64, 63), nm + ".Msb");
    return b.CreateNeg(msb, nm + ".Mask");
}

static Value* EmitSigCpuidVendor(IRBuilder<>& b, Value* ebx, Value* ecx, Value* edx)
{
    Value* db = b.CreateXor(ebx, b.getInt32(0x7263694Du), "WhpkVendorDb");
    Value* dc = b.CreateXor(ecx, b.getInt32(0x666F736Fu), "WhpkVendorDc");
    Value* dd = b.CreateXor(edx, b.getInt32(0x76482074u), "WhpkVendorDd");
    Value* o1 = b.CreateOr(db, dc, "WhpkVendorO1");
    Value* d = b.CreateOr(o1, dd, "WhpkVendorD");
    return EmitEqNormalize(b, d, "WhpkVendor");
}

static Value* EmitSigCpuidHv1(IRBuilder<>& b, Value* eaxl1)
{
    Value* d = b.CreateXor(eaxl1, b.getInt32(0x31237648u), "WhpkHv1D");
    return EmitEqNormalize(b, d, "WhpkHv1");
}

static Value* EmitSigCpuidNotNested(IRBuilder<>& b, Value* edxl3)
{
    Value* bit = b.CreateAnd(edxl3, b.getInt32(1u << 27), "WhpkNotNestedBit");
    Value* nzmask = EmitNzNormalize(b, bit, "WhpkNotNestedNz");
    return b.CreateNot(nzmask, "WhpkNotNestedMask");
}

static Value* EmitSigCpuidHcallBits(IRBuilder<>& b, Value* eaxl3)
{
    const uint32_t need = (1u << 1) | (1u << 5);
    Value* masked = b.CreateAnd(eaxl3, b.getInt32(need), "WhpkHcallM");
    Value* d = b.CreateXor(masked, b.getInt32(need), "WhpkHcallD");
    return EmitEqNormalize(b, d, "WhpkHcall");
}

static Value* EmitSigCpuidRecommend(IRBuilder<>& b, Value* eaxl4)
{
    return EmitNzNormalize(b, eaxl4, "WhpkRecommend");
}

static Value* EmitSigCpuidMaxVp(IRBuilder<>& b, Value* eaxl5)
{
    return EmitNzNormalize(b, eaxl5, "WhpkMaxVp");
}

static Value* EmitSigCpuidHwFeatures(IRBuilder<>& b, Value* eaxl6)
{
    const uint32_t need = (1u << 0) | (1u << 3);
    Value* masked = b.CreateAnd(eaxl6, b.getInt32(need), "WhpkHwfeatM");
    Value* d = b.CreateXor(masked, b.getInt32(need), "WhpkHwfeatD");
    return EmitEqNormalize(b, d, "WhpkHwfeat");
}

static Value* EmitSigQpf(IRBuilder<>& b, Module& m, Function& f)
{
    LLVMContext& ctx = m.getContext();
    Type* i32 = Type::getInt32Ty(ctx);
    Type* i64 = Type::getInt64Ty(ctx);
    Type* ptrty = PointerType::getUnqual(ctx);

    FunctionCallee qpf = m.getOrInsertFunction("QueryPerformanceFrequency", FunctionType::get(i32, {ptrty}, false));

    IRBuilder<> ab(&f.getEntryBlock(), f.getEntryBlock().getFirstInsertionPt());
    AllocaInst* slot = ab.CreateAlloca(i64, nullptr, "WhpkQpfSlot");
    slot->setAlignment(Align(8));

    b.CreateCall(qpf, {slot}, "WhpkQpfRet");
    LoadInst* freq = b.CreateLoad(i64, slot, true, "WhpkQpfFreq");
    freq->setAlignment(Align(8));
    Value* d = b.CreateXor(freq, ConstantInt::get(i64, 10000000ULL), "WhpkQpfD");
    return EmitEqNormalize(b, d, "WhpkQpf");
}

static uint64_t KusdBase()
{
    return ((uint64_t)KusdBaseHi << 32) | (uint64_t)KusdBaseLo;
}

static Value* EmitSigKusdInterruptTime(IRBuilder<>& b, Module& m)
{
    LLVMContext& ctx = m.getContext();
    Type* i32 = Type::getInt32Ty(ctx);
    Type* i64 = Type::getInt64Ty(ctx);

    FunctionCallee sleepfn = m.getOrInsertFunction("Sleep", FunctionType::get(Type::getVoidTy(ctx), {i32}, false));

    uint64_t addr = KusdBase() + (uint64_t)KusdInterruptTimeOff;
    Value* p = b.CreateIntToPtr(ConstantInt::get(i64, addr), PointerType::getUnqual(ctx), "WhpkKusdIntP");

    LoadInst* t0 = b.CreateLoad(i64, p, true, "WhpkKusdIntT0");
    t0->setAlignment(Align(8));

    b.CreateCall(sleepfn, {ConstantInt::get(i32, InterruptSleepMs)}, "");

    LoadInst* t1 = b.CreateLoad(i64, p, true, "WhpkKusdIntT1");
    t1->setAlignment(Align(8));

    Value* d = b.CreateSub(t1, t0, "WhpkKusdIntD");
    return EmitNzNormalize(b, d, "WhpkKusdInt");
}

static Value* EmitEntryProbe(Function& f, Module& m, uint64_t kbase, PerFuncSummary& s)
{
    LLVMContext& ctx = m.getContext();
    Type* i32 = Type::getInt32Ty(ctx);
    Type* i64 = Type::getInt64Ty(ctx);

    BasicBlock& entry = f.getEntryBlock();
    IRBuilder<> b(&entry, entry.getFirstInsertionPt());

    Value* qb1 = EmitCpuid(b, 0x00000001u, "WhpkCpuidBasic1");
    Value* q0 = EmitCpuid(b, 0x40000000u, "WhpkCpuid0");
    Value* q1 = EmitCpuid(b, 0x40000001u, "WhpkCpuid1");
    Value* q3 = EmitCpuid(b, 0x40000003u, "WhpkCpuid3");
    Value* q4 = EmitCpuid(b, 0x40000004u, "WhpkCpuid4");
    Value* q5 = EmitCpuid(b, 0x40000005u, "WhpkCpuid5");
    Value* q6 = EmitCpuid(b, 0x40000006u, "WhpkCpuid6");

    Value* signalmask = ConstantInt::get(i64, ~0ULL);
    unsigned signalsemitted = 0;
    auto andin = [&](Value* sig)
    {
        signalmask = b.CreateAnd(signalmask, sig, "WhpkSigM");
        ++signalsemitted;
    };

    Value* ebx = b.CreateExtractValue(q0, 1, "WhpkC0Ebx");
    Value* ecx = b.CreateExtractValue(q0, 2, "WhpkC0Ecx");
    Value* edx = b.CreateExtractValue(q0, 3, "WhpkC0Edx");
    andin(EmitSigCpuidVendor(b, ebx, ecx, edx));

    Value* eaxc1 = b.CreateExtractValue(q1, 0, "WhpkC1Eax");
    andin(EmitSigCpuidHv1(b, eaxc1));

    Value* edxc3 = b.CreateExtractValue(q3, 3, "WhpkC3Edx");
    andin(EmitSigCpuidNotNested(b, edxc3));

    Value* eaxc3 = b.CreateExtractValue(q3, 0, "WhpkC3Eax");
    andin(EmitSigCpuidHcallBits(b, eaxc3));

    Value* eaxc4 = b.CreateExtractValue(q4, 0, "WhpkC4Eax");
    andin(EmitSigCpuidRecommend(b, eaxc4));

    Value* eaxc5 = b.CreateExtractValue(q5, 0, "WhpkC5Eax");
    andin(EmitSigCpuidMaxVp(b, eaxc5));

    Value* eaxc6 = b.CreateExtractValue(q6, 0, "WhpkC6Eax");
    andin(EmitSigCpuidHwFeatures(b, eaxc6));

    andin(EmitSigQpf(b, m, f));

    andin(EmitSigKusdInterruptTime(b, m));

    Value* ebxv = b.CreateExtractValue(q0, 1, "WhpkPgEbx");
    Value* ecxv = b.CreateExtractValue(q0, 2, "WhpkPgEcx");
    Value* edxv = b.CreateExtractValue(q0, 3, "WhpkPgEdx");
    Value* db = b.CreateXor(ebxv, b.getInt32(0x7263694Du), "WhpkPgDb");
    Value* dc = b.CreateXor(ecxv, b.getInt32(0x666F736Fu), "WhpkPgDc");
    Value* dd = b.CreateXor(edxv, b.getInt32(0x76482074u), "WhpkPgDd");
    Value* vo1 = b.CreateOr(db, dc, "WhpkPgVo1");
    Value* vd = b.CreateOr(vo1, dd, "WhpkPgVd");
    Value* ismshv = EmitEqNormalize(b, vd, "WhpkPgIsMs");

    Value* ecxb1 = b.CreateExtractValue(qb1, 2, "WhpkPgB1Ecx");
    Value* hvbit = b.CreateLShr(ecxb1, ConstantInt::get(i32, 31u), "WhpkPgHvBit");
    Value* hvbitand = b.CreateAnd(hvbit, ConstantInt::get(i32, 1u), "WhpkPgHvBitM");
    Value* hvbitmask = EmitNzNormalize(b, hvbitand, "WhpkPgHvBit");

    Value* eaxv = b.CreateExtractValue(q0, 0, "WhpkPgEax");
    Value* lo1 = b.CreateOr(eaxv, ebxv, "WhpkPgLo1");
    Value* lo2 = b.CreateOr(ecxv, edxv, "WhpkPgLo2");
    Value* lall = b.CreateOr(lo1, lo2, "WhpkPgLall");
    Value* leafnz = EmitNzNormalize(b, lall, "WhpkPgLeafNz");

    Value* notms = b.CreateNot(ismshv, "WhpkPgNotMs");
    Value* hvorleaf = b.CreateOr(hvbitmask, leafnz, "WhpkPgAnyHv");
    Value* bypass = b.CreateAnd(notms, hvorleaf, "WhpkPgBypass");

    Value* finalmask = b.CreateOr(bypass, signalmask, "WhpkFinalM");

    Value* kbasec = ConstantInt::get(i64, kbase);
    Value* klive = b.CreateAnd(kbasec, finalmask, "WhpkK");

    s.SignalsEmitted = signalsemitted;
    s.SitesEmitted = 1;
    return klive;
}

static void RewriteOperand(Instruction& i, unsigned opidx, ConstantInt* ci, Value* klive64, uint64_t kbase, PerFuncSummary& s)
{
    LLVMContext& ctx = i.getContext();
    unsigned bw = ci->getBitWidth();
    IntegerType* iwty = IntegerType::get(ctx, bw);

    uint64_t plain = ci->getZExtValue();
    uint64_t mask = (bw == 64) ? ~0ULL : ((1ULL << bw) - 1ULL);
    uint64_t kw = kbase & mask;
    uint64_t kct = (plain ^ kw) & mask;

    IRBuilder<> ub(&i);
    Value* kslice = klive64;
    if (bw != 64) kslice = ub.CreateTrunc(klive64, iwty, "WhpkKTr");
    Value* kctv = ConstantInt::get(iwty, kct);
    Value* dec = ub.CreateXor(kctv, kslice, "WhpkC");
    i.setOperand(opidx, dec);

    ++s.ConstsEncrypted;
    ++s.UsesRewritten;
}

static bool ProcessFunction(Function& f, Value* klive, uint64_t kbase, PerFuncSummary& s)
{
    DominatorTree dt;
    dt.recalculate(f);
    LoopInfo* li = new LoopInfo();
    li->analyze(dt);

    DenseSet<BasicBlock*> covered;
    BasicBlock& entry = f.getEntryBlock();

    for (BasicBlock& bb : f)
    {
        if (&bb == &entry) continue;
        if (Loop* l = li->getLoopFor(&bb))
        {
            if (l->getHeader() == &bb)
            {
                ++s.LoopHdrSkipped;
                continue;
            }
        }

        for (Instruction& i : bb)
        {
            if (s.UsesRewritten >= PerFnCap)
            {
                ++s.CapHit;
                break;
            }

            if (isa<IntrinsicInst>(&i)) continue;
            if (isa<PHINode>(&i)) continue;
            if (isa<SwitchInst>(&i)) continue;

            CallBase* cb = dyn_cast<CallBase>(&i);
            unsigned calledidx = cb ? cb->getCalledOperandUse().getOperandNo() : ~0u;

            GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(&i);
            DenseSet<unsigned> gepstructslots;
            if (gep)
            {
                unsigned opno = 1;
                for (auto it = gep_type_begin(gep), end = gep_type_end(gep); it != end; ++it, ++opno)
                {
                    if (it.isStruct()) gepstructslots.insert(opno);
                }
            }

            for (unsigned o = 0; o < i.getNumOperands(); ++o)
            {
                if (cb && o == calledidx) continue;
                if (gep && gepstructslots.count(o)) continue;

                auto* ci = dyn_cast<ConstantInt>(i.getOperand(o));
                if (!ci) continue;

                unsigned bw = ci->getBitWidth();
                if (bw < MinBitwidth) continue;
                if (bw > MaxBitwidth) continue;
                if (bw == 1) continue;

                RewriteOperand(i, o, ci, klive, kbase, s);
                covered.insert(&bb);
                if (s.UsesRewritten >= PerFnCap)
                {
                    ++s.CapHit;
                    break;
                }
            }
            if (s.UsesRewritten >= PerFnCap) break;
        }
    }

    s.BbsCovered = (unsigned)covered.size();
    delete li;
    return s.UsesRewritten > 0;
}

bool RunWHPKill(Module& m)
{
    if (!WHPKillEnable) return false;

    uint64_t seed = ((uint64_t)WhpkillRng() << 32) | (uint64_t)WhpkillRng();
    std::mt19937_64 local(seed);

    bool changed = false;

    for (Function& f : m)
    {
        if (f.isDeclaration() || f.empty()) continue;
        if (!HasWHPKillAnnotation(f)) continue;
        if (HasNoWHPKillAnnotation(f)) continue;

        PerFuncSummary s;
        s.FuncName = f.getName().str();

        uint64_t kbase = 0;
        while (kbase == 0) kbase = Rand64(local);
        s.KBase = kbase;

        Value* klive = EmitEntryProbe(f, m, kbase, s);
        bool fnchanged = ProcessFunction(f, klive, kbase, s);

        if (fnchanged || s.SitesEmitted > 0) changed = true;
    }

    return changed;
}

PreservedAnalyses WHPKillPass::run(Module& m, ModuleAnalysisManager&)
{
    bool changed = RunWHPKill(m);
    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}