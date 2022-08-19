// ORCA : 8/19/2022, PROGRAM THAT ACT LIKE A EDR, THAT HOOKS SOME SYSCALL
//                   AND PRINT SOME OF THERE ARGS   



#include <Windows.h>
#include <stdio.h>
#include "Hook.h"








BOOL APIENTRY DllMain( HMODULE hModule, DWORD  Reason, LPVOID lpReserved){

    HANDLE hThread = NULL;

    switch (Reason){

        case DLL_PROCESS_ATTACH:
        {
            hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InitializeHooks, NULL, NULL, NULL);
            if (hThread != NULL)
                CloseHandle(hThread);
            break;
        }

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

