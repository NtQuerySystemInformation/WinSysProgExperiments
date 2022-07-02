#include "defs.hpp"
#include "exec.h"
#include <Windows.h>
#include <iostream>
#include <inttypes.h>

//Pending here:
   //1.-Make string argument by default as explorer.exe.
void Injection::MainExecFunction() noexcept
{
    auto proc = std::make_unique<TargetProcess>(L"calc.exe", GetModuleHandle(NULL));
    if (proc == nullptr) {
        std::cerr << "Could not create TargetProcess object for spawning process\n";
        return;
    }
    if (!Injection::CreatedSuspendedProcess(proc.get()))
    {
        std::printf("Could not create suspended process, Last Error is %x\n", GetLastError());
        return;
    }
#ifdef _DEBUG
    std::printf("The entrypoint function for created process is RCX: 0x%" PRIx64 "\n", proc.get()->GetMainThreadContext().Rcx);
#endif 
    if (!Injection::CreateAndRelocateDllInRemoteProcess(proc.get()))
    {
        std::printf("Could not create suspended process, Last Error is %x\n", GetLastError());
    }
    //HOOK entrypoint function with length disassembler.
}

//1.-Create suspended process and get procinfo and main thread context.
//Get RCX for eventual hooking.
bool Injection::CreatedSuspendedProcess(TargetProcess* proc) noexcept
{
	return proc->CreateProcessSuspendedToInject() ? true : false;
}

//2.-Create section, create views, relocate.
bool Injection::CreateAndRelocateDllInRemoteProcess(TargetProcess* process) noexcept
{
    //Does this work?, verify.
    return process->genSectionAndViews(process->getCurrentModule(), const_cast<PPROCESS_INFORMATION>(&process->getProcInfo()));
}

//3.-Using RCX (address of entrypoint function), patch the bytes based on encoding of instructions.
//To read:
//      -Encoding of instructions in x64 and x64 Hooks with length disassembler.
//-After Hooking, REBUILD necessary IAT, and then resume main thread.
bool Injection::HookEntrypointFunction(TargetProcess* process) 
{
    return false;
}