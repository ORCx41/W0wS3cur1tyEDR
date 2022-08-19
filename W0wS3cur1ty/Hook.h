#pragma once



#ifndef _HOOK_H
#define _HOOK_H




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
	PVOID		lpBytesBuffer);



NTSTATUS WINAPI MyNtWriteVirtualMemory(
	HANDLE      ProcessHandle,
	PVOID       BaseAddress,
	PVOID       Buffer,
	ULONG       NumberOfBytesToWrite,
	PULONG      NumberOfBytesWritten);



NTSTATUS WINAPI MyNtProtectVirtualMemory(
	HANDLE      ProcessHandle,
	PVOID*		BaseAddress,
	PULONG      NumberOfBytesToProtect,
	ULONG       NewAccessProtection,
	PULONG      OldAccessProtection);



NTSTATUS WINAPI MyNtAllocateVirtualMemory(
	HANDLE      ProcessHandle,
	PVOID*		BaseAddress,
	ULONG       ZeroBits,
	PULONG      RegionSize,
	ULONG       AllocationType,
	ULONG       Protect);




BOOL CreateConsole();
BOOL InitializeHooks();			// entry point function
VOID WriteBytes(unsigned char* pAddress, SIZE_T Size);
VOID ReportError(PTSTR lpszFunction, DWORD dw);




#endif // !_HOOK_H
