#pragma once

#include "def.h"

#include <TlHelp32.h>
#include <iostream>

struct HOOK_INFO
{
	uintptr_t entryAddress;
	uintptr_t realFuncAddress;
};

int main();

INT						FindProcessId(LPCSTR szExeName);
PPEB					FindRemotePEB(HANDLE hProcess);
PIMAGE_DATA_DIRECTORY	ReadRemoteDataDirectoryRVA(HANDLE hProcess, LPVOID lpImageBaseAddress, INT nIndex);
HOOK_INFO*				GetHookInfo(HANDLE hProcess, PIMAGE_DATA_DIRECTORY pImageImportDirectory, LPVOID lpImageBaseAddress, LPCSTR szLibName, LPCSTR szFuncName);
HOOK_INFO*				GetHookInfo(HANDLE hProcess, LPCSTR szLibName, LPCSTR szFuncName);
BOOL					SwapEntry(HANDLE hProcess, HOOK_INFO* pHookInfo, uintptr_t newEntry);