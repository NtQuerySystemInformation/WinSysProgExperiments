#include <iostream>
#include "defs.hpp"
#include "exec.h"
#include <inttypes.h>

//Pending:
// 1.Proper relocations of PE in x64, is it possible for our interest?
// 2.Example for x64 hooking: http://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html

//Steps:
//1.-Get a handle of the current dll module
//2.-
//3.-

uint32_t main(void)
{
    auto proc = std::make_unique<TargetProcess>(L"calc.exe");
    if (proc == nullptr){
        std::cerr << "Could not create TargetProcess object for spawning process\n";
        return EXIT_FAILURE;
    }
    if (!Injection::CreatedSuspendedProcess(proc.get()))
    {
        std::printf("Could not create suspended process, Last Error is %x\n", GetLastError());
        return EXIT_FAILURE;
    }
#ifdef _DEBUG
    std::printf("The entrypoint function for created process is RCX: 0x%" PRIx64 "\n", proc.get()->GetMainThreadContext().Rcx);
#endif 
    //

    return EXIT_SUCCESS;
}