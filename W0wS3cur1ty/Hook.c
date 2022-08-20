#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>

#include "MinHook.h"
#include "Hook.h"

#pragma comment (lib, "minhook.x64.lib")
#pragma warning( disable : 4996)


#define NtCurrentThread()	( (HANDLE)(LONG_PTR) -2 )
#define NtCurrentProcess()	( (HANDLE)(LONG_PTR) -1 )
#define NtLastError()		( NtCurrentTeb()->LastErrorValue )
#define NtLastStatus()		( NtCurrentTeb()->LastStatusValue )
#define NT_SUCCESS(STATUS)  ( (NTSTATUS)(STATUS) >= 0 )




typedef NTSTATUS (NTAPI* fnNtCreateThreadEx)(
	OUT		PHANDLE		hThread,
	IN		ACCESS_MASK DesiredAccess,
	IN		PVOID		ObjectAttributes,
	IN		HANDLE		ProcessHandle,
	IN		PVOID		lpStartAddress,
	IN		PVOID		lpParameter,
	IN		ULONG		Flags,
	IN		SIZE_T		StackZeroBits,
	IN		SIZE_T		SizeOfStackCommit,
	IN		SIZE_T		SizeOfStackReserve,
	OUT		PVOID		lpBytesBuffer
);


typedef NTSTATUS (NTAPI* fnNtWriteVirtualMemory)(
	IN		HANDLE      ProcessHandle,
	IN		PVOID       BaseAddress,
	IN		PVOID       Buffer,
	IN		ULONG       NumberOfBytesToWrite,
	OUT		PULONG      NumberOfBytesWritten
);


typedef NTSTATUS (NTAPI* fnNtProtectVirtualMemory)(
	IN		HANDLE      ProcessHandle,
	IN OUT	PVOID*		BaseAddress,
	IN OUT	PULONG      NumberOfBytesToProtect,
	IN		ULONG       NewAccessProtection,
	OUT		PULONG      OldAccessProtection
	
);


typedef NTSTATUS (NTAPI* fnNtAllocateVirtualMemory)(
	IN		HANDLE      ProcessHandle,
	IN OUT	PVOID*		BaseAddress,
	IN		ULONG       ZeroBits,
	IN OUT	PULONG      RegionSize,
	IN		ULONG       AllocationType,
	IN		ULONG       Protect
	
);



typedef struct _NTAPI_STRUCT {

	fnNtCreateThreadEx			NtCreateThreadEx;
	fnNtWriteVirtualMemory		NtWriteVirtualMemory;
	fnNtProtectVirtualMemory	NtProtectVirtualMemory;
	fnNtAllocateVirtualMemory   NtAllocateVirtualMemory;

}NTAPI_STRUCT, *PNTAPI_STRUCT;


NTAPI_STRUCT GS = { 0 };



typedef struct {

	HANDLE hProc;
	HANDLE hOConsole;
	DWORD  Pid;

}CONSOLE;

CONSOLE Console = { 0 };
// https://github.com/rad9800/WTSRM/blob/master/WTSRM/entry.cpp#L34
#define PRINT( STR, ... )                                                                   \
    if (1) {                                                                                \
        LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfW( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleW( Console.hOConsole, buf, len, NULL, NULL );			    \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  

#define PWND(A, S)   									    \
			WriteBytes((unsigned char*)A, (SIZE_T) S);			    \


BOOL CreateConsole() {
	
	if (!FreeConsole()) {
		ReportError(L"FreeConsole", GetLastError());
		return FALSE;
	}
	
	if (!AllocConsole()) {
		ReportError(L"AllocConsole", GetLastError());
		return FALSE;
	}

	Console.Pid = GetCurrentProcessId();
	Console.hProc = GetCurrentProcess();
	
	if ((Console.hOConsole = GetStdHandle(STD_OUTPUT_HANDLE)) == NULL ) {
		ReportError(L"GetStdHandle", GetLastError());
		return FALSE;
	}


	return TRUE;
}



BOOL InitializeHooks() {

	if (!CreateConsole()) {
		TerminateProcess(NtCurrentProcess(), -1);
	}

	HMODULE hModule = NULL;
	LONG	Merr	= NULL;


	if ((hModule = GetModuleHandleW(L"NTDLL.DLL")) == NULL) {
		return FALSE;
	}

	
	if ((Merr = MH_Initialize()) != MH_OK) {
		ReportError(L"MH_Initialize", Merr);
		return FALSE;
	}


	if (
		((Merr = MH_CreateHookApi(TEXT("ntdll"), "NtCreateThreadEx", MyNtCreateThreadEx, (LPVOID*)&GS.NtCreateThreadEx) != MH_OK)) ||
		((Merr = MH_CreateHookApi(TEXT("ntdll"), "NtWriteVirtualMemory", MyNtWriteVirtualMemory, (LPVOID*)&GS.NtWriteVirtualMemory) != MH_OK)) ||
		((Merr = MH_CreateHookApi(TEXT("ntdll"), "NtAllocateVirtualMemory", MyNtAllocateVirtualMemory, (LPVOID*)&GS.NtAllocateVirtualMemory) != MH_OK)) ||
		((Merr = MH_CreateHookApi(TEXT("ntdll"), "NtProtectVirtualMemory", MyNtProtectVirtualMemory, (LPVOID*)&GS.NtProtectVirtualMemory) != MH_OK))
		){
		ReportError(L"MH_CreateHookApi", Merr);
		return FALSE;
	}
	
	if ((Merr = MH_EnableHook(MH_ALL_HOOKS)) != NO_ERROR) {
		ReportError(L"MH_EnableHook", Merr);
		return FALSE;
	}
}


VOID WriteBytes(unsigned char* pAddress, SIZE_T Size) {
	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			PRINT(L"\n\t");
		}
		PRINT(L" %02X", pAddress[i]);
	}
	PRINT(L"\n");
}



NTSTATUS WINAPI MyNtCreateThreadEx(
	PHANDLE		hThread,
	ACCESS_MASK DesiredAccess,
	PVOID		ObjectAttributes,
	HANDLE		ProcessHandle,
	PVOID		lpStartAddress,
	PVOID		lpParameter,
	ULONG		Flags,
	SIZE_T		StackZeroBits,
	SIZE_T		SizeOfStackCommit,
	SIZE_T		SizeOfStackReserve,
	PVOID		lpBytesBuffer){


	PRINT(L"\n[!] NtCreateThreadEx : STARTING NEW THREAD AT 0x%p \n", lpStartAddress);

	return GS.NtCreateThreadEx(
		hThread, DesiredAccess, ObjectAttributes, ProcessHandle,
		lpStartAddress, lpParameter, Flags, StackZeroBits,
		SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
}



NTSTATUS WINAPI MyNtWriteVirtualMemory(
	HANDLE      ProcessHandle,
	PVOID       BaseAddress,
	PVOID       Buffer,
	ULONG       NumberOfBytesToWrite,
	PULONG      NumberOfBytesWritten) {


	PRINT(L"\n[!] NtWriteVirtualMemory : WRITING TO 0x%p [ OF SIZE %d ]\n", (PVOID)BaseAddress, (unsigned int)NumberOfBytesToWrite);
	
	return GS.NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}




NTSTATUS WINAPI MyNtProtectVirtualMemory(
	HANDLE      ProcessHandle,
	PVOID*		BaseAddress,
	PULONG      NumberOfBytesToProtect,
	ULONG       NewAccessProtection,
	PULONG      OldAccessProtection) {

	PRINT(L"\n[!] NtProtectVirtualMemory : MEMORY AT : 0x%p  [ OF SIZE %d ] : ", (PVOID)*BaseAddress, (unsigned int)*NumberOfBytesToProtect);

	if ((NewAccessProtection & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
		PRINT(L"PAGE_EXECUTE_READWRITE IS DETECTED \n");
		PWND(*BaseAddress, *NumberOfBytesToProtect);
		MessageBox(NULL, L"YOUR A$$ IS BUSTED", L"LOL", MB_OK);
	}
	else {
		PRINT(L"CONTINUING ...\n");
	}

	return  GS.NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}



NTSTATUS WINAPI MyNtAllocateVirtualMemory(
	HANDLE      ProcessHandle,
	PVOID*		BaseAddress,
	ULONG       ZeroBits,
	PULONG      RegionSize,
	ULONG       AllocationType,
	ULONG       Protect) {


	NTSTATUS STATUS = 0x0;


	PRINT(L"\n[!] NtAllocateVirtualMemory : ALLOCATING AT : 0x%p  [ OF SIZE %d ] : ", (PVOID)*BaseAddress, (unsigned int)*RegionSize);

	if ((Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
		PRINT(L"PAGE_EXECUTE_READWRITE IS DETECTED \n");
		MessageBox(NULL, L"YOUR A$$ IS BUSTED", L"LOL", MB_OK);
	}

	if (*BaseAddress == NULL) {
		STATUS = GS.NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
		PRINT(L"UPDATED ADDRESS AT : 0x%p ...\n", (PVOID)*BaseAddress);
		return STATUS;
	}
	else {
		PRINT(L"CONTINUING ...\n");
		return GS.NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	}

	// wont reach this:
	return STATUS;
}





VOID ReportError(PTSTR lpszFunction, DWORD dw) {

	LPVOID	lpMsgBuf;
	LPVOID	lpDisplayBuf;

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0,
		NULL
	);

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 64) * sizeof(TCHAR));
	if (lpDisplayBuf == NULL)
		return;

	StringCchPrintf((LPTSTR)lpDisplayBuf, LocalSize(lpDisplayBuf) / sizeof(TCHAR), TEXT("%s Failed With Error [ %d | 0x%0.8X ] : %s"), lpszFunction, dw, dw, lpMsgBuf);
	
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("ERROR"), MB_OK | MB_ICONERROR);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	
	//ExitProcess(1);
}
