#include <iostream>
#include <Windows.h>
#include "defs.hpp"
#include "exec.h"

//Pending after it all works:
//  1.-Organize header files in folders: "core", "defs", "hooks".
//  2.-Can you encapsulate the classes even more? -> Turn Injection namespace in methods of one class.
//  3.-STATICALLY LINK LIBRARIES! (Change code generation to avoid dependencies)
//  4.-Allocate console to check for output.

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Injection::MainExecFunction();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

