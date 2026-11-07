#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

struct WHPKillPass : llvm::PassInfoMixin<WHPKillPass>
{
    llvm::PreservedAnalyses run(llvm::Module& m, llvm::ModuleAnalysisManager&);
};

bool RunWHPKill(llvm::Module& m);

extern llvm::cl::opt<bool> WHPKillEnable;