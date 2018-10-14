#include "main.h"

int main()
{
	INT nPid = FindProcessId("notepad.exe");

	if (!nPid)
	{
		printf("FindProcessId() failed at line %d\n", __LINE__);
	}
	else
	{
		HANDLE hProcess = OpenProcess
		(
			PROCESS_ALL_ACCESS,
			FALSE,
			nPid
		);

		if (!hProcess)
		{
			printf("OpenProcess() failed (%d) at line %d\n", GetLastError(), __LINE__);
		}
		else
		{
			HOOK_INFO* info = GetHookInfo(hProcess, "user32.dll", "TranslateMessage");

			if (!info)
			{
				printf("GetHookInfo() failed at line %d\n", __LINE__);
			}
			else
			{
				BOOL bSuccess = SwapEntry(hProcess, info, 0x000);
				bSuccess = SwapEntry(hProcess, info, info->realFuncAddress);

				if (!bSuccess)
				{
					printf("SwapEntry() failed at line %d\n", __LINE__);
				}
			}
		}
	}

	

	system("pause");
}

INT FindProcessId(LPCSTR szExeName)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snapshot == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot() failed (%d) at line %d\n", GetLastError(), __LINE__);
		return 0;
	}

	PROCESSENTRY32 entry{ 0 }; entry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(snapshot, &entry))
	{
		do
		{
			if (!_stricmp(entry.szExeFile, szExeName))
			{
				CloseHandle(snapshot);
				return entry.th32ProcessID;
			}

		} while (Process32Next(snapshot, &entry));
	}
	else
	{
		printf("Process32First() failed (%d) at line %d\n", GetLastError(), __LINE__);
		return 0;
	}

	CloseHandle(snapshot);
	return 0;
}

PPEB FindRemotePEB(HANDLE hProcess)
{
	/*HMODULE hNTDll = LoadLibraryA("NTDll");

	if (!hNTDll)
	{
		printf("LoadLibrary() failed (%d) at line %d\n", GetLastError(), __LINE__);
		return 0;
	}

	FARPROC fpNtQueryInformationProcess = GetProcAddress
	(
		hNTDll,
		"NtQueryInformationProcess"
	);

	if (!fpNtQueryInformationProcess)
	{
		printf("GetProcAddress() failed (%d) at line %d\n", GetLastError(), __LINE__);
		return 0;
	}

	__NtQueryInformationProcess NtQueryInformationProcess = 
		(__NtQueryInformationProcess)fpNtQueryInformationProcess;

	PROCESS_BASIC_INFORMATION basicInfo;
	ULONG returnLength;

	NTSTATUS status = NtQueryInformationProcess
	(
		hProcess,
		ProcessBasicInformation,
		&basicInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		&returnLength
	);

	if (status)
	{
		printf("NtQueryInformationProcess() failed (%d) at line %d\n", GetLastError(), __LINE__);
		return 0;
	}

	return basicInfo.PebBaseAddress;*/

	HMODULE hmNtDll = LoadLibraryA("NtDll.dll");

	const auto NtQueryInformationProcessFn =
		(__NtQueryInformationProcess)GetProcAddress(
			hmNtDll,
			"NtQueryInformationProcess"
		);

	PROCESS_BASIC_INFORMATION basicInfo{ 0 };

	auto status = NtQueryInformationProcessFn
	(
		hProcess,
		ProcessBasicInformation,
		&basicInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		nullptr
	);

	PPEB pPEB = new PEB();

	if (!ReadProcessMemory
	(
		hProcess,
		basicInfo.PebBaseAddress,
		pPEB,
		sizeof(PEB),
		nullptr
	))
	{
		throw std::exception("couldn't read remote peb");
		return nullptr;
	}

	return pPEB;
}

PIMAGE_DATA_DIRECTORY ReadRemoteDataDirectoryRVA(HANDLE hProcess, LPVOID lpImageBaseAddress, INT nIndex)
{
	BYTE* buffer = (BYTE*)malloc(BUFFER_SIZE);

	if (!buffer)
	{
		printf("malloc() failed (%d) at line %d\n", GetLastError(), __LINE__);
		return 0;
	}

	ZeroMemory(buffer, BUFFER_SIZE);

	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		lpImageBaseAddress,
		buffer,
		BUFFER_SIZE,
		0
	);

	if (!bSuccess)
	{
		printf("ReadProcessMemory() failed (%d) at line %d\n", GetLastError(), __LINE__);
		free(buffer);
		return 0;
	}

	PIMAGE_DOS_HEADER pDosHd = (PIMAGE_DOS_HEADER)buffer;

	if (pDosHd->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Invalid DOS header at line %d\n", __LINE__);
		free(buffer);
		return 0;
	}

	PIMAGE_NT_HEADERS pNtHd = (PIMAGE_NT_HEADERS)(buffer + pDosHd->e_lfanew);

	if (pNtHd->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && pNtHd->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		printf("Invalid NT header at line %d\n", __LINE__);
		free(buffer);
		return 0;
	}

	return &pNtHd->OptionalHeader.DataDirectory[nIndex];
}

HOOK_INFO* GetHookInfo(HANDLE hProcess, PIMAGE_DATA_DIRECTORY pImageImportDirectory, LPVOID lpImageBaseAddress, LPCSTR szLibName, LPCSTR szFuncName)
{
	BYTE* buffer = (BYTE*)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR) * 50);

	if (!buffer)
	{
		printf("malloc() failed (%d) at line %d\n", GetLastError(), __LINE__);
		return 0;
	}

	ZeroMemory(buffer, sizeof(IMAGE_IMPORT_DESCRIPTOR) * 50);

	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		(LPCVOID)((uintptr_t)lpImageBaseAddress + pImageImportDirectory->VirtualAddress),
		buffer,
		sizeof(IMAGE_IMPORT_DESCRIPTOR) * 50,
		0
	);

	if (!bSuccess)
	{
		printf("ReadProcessMemory() failed (%d) at line %d\n", GetLastError(), __LINE__);
		return 0;
	}

	HOOK_INFO* info = (HOOK_INFO*)malloc(sizeof(HOOK_INFO));
	
	if (!info)
	{
		printf("malloc() failed (%d) at line %d\n", GetLastError(), __LINE__);
		return 0;
	}

	ZeroMemory(info, sizeof(HOOK_INFO));

	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)buffer;

	while (pImageImportDescriptor->Characteristics)
	{
		BYTE* libNameBuffer = (BYTE*)malloc(SMALL_BUFFER_SIZE);

		if (!libNameBuffer)
		{
			printf("malloc() failed (%d) at line %d\n", GetLastError(), __LINE__);
			return 0;
		}

		ZeroMemory(libNameBuffer, SMALL_BUFFER_SIZE);

		bSuccess = ReadProcessMemory
		(
			hProcess,
			(LPCVOID)((uintptr_t)lpImageBaseAddress + pImageImportDescriptor->Name),
			libNameBuffer,
			SMALL_BUFFER_SIZE,
			0
		);

		if (!bSuccess)
		{
			printf("ReadProcessMemory() failed (%d) at line %d\n", GetLastError(), __LINE__);
			return 0;
		}

		INT iteration = 0;
		uintptr_t firstRVA;
		while (1)
		{
			IMAGE_THUNK_DATA thunkDataILT, thunkDataIAT;

			bSuccess = ReadProcessMemory
			(
				hProcess,
				(LPCVOID)((uintptr_t)lpImageBaseAddress + pImageImportDescriptor->OriginalFirstThunk + (iteration * sizeof(PVOID))),
				&thunkDataILT,
				sizeof(IMAGE_THUNK_DATA),
				0
			);

			if (!bSuccess)
			{
				printf("ReadProcessMemory() failed (%d) at line %d\n", GetLastError(), __LINE__);
				return 0;
			}

			bSuccess = ReadProcessMemory
			(
				hProcess,
				(LPCVOID)((uintptr_t)lpImageBaseAddress + pImageImportDescriptor->FirstThunk + (iteration * sizeof(PVOID))),
				&thunkDataIAT,
				sizeof(IMAGE_THUNK_DATA),
				0
			);

			if (!bSuccess)
			{
				printf("ReadProcessMemory() failed (%d) at line %d\n", GetLastError(), __LINE__);
				return 0;
			}

			if (!thunkDataILT.u1.AddressOfData && !thunkDataIAT.u1.Function)
				break;

			if (iteration == 0)
				firstRVA = thunkDataILT.u1.AddressOfData;
			else if (abs(thunkDataILT.u1.AddressOfData - firstRVA) < 0x5000)
			{
				BYTE* funcNameBuffer = (BYTE*)malloc(SMALL_BUFFER_SIZE);

				if (!funcNameBuffer)
				{
					printf("malloc() failed (%d) at line %d\n", GetLastError(), __LINE__);
					return 0;
				}

				ZeroMemory(funcNameBuffer, SMALL_BUFFER_SIZE);

				bSuccess = ReadProcessMemory
				(
					hProcess,
					(LPCVOID)((uintptr_t)lpImageBaseAddress + thunkDataILT.u1.AddressOfData),
					funcNameBuffer,
					SMALL_BUFFER_SIZE,
					0
				);

				if (!bSuccess)
				{
					printf("ReadProcessMemory() failed (%d) at line %d\n", GetLastError(), __LINE__);
					return 0;
				}

				PIMAGE_IMPORT_BY_NAME pImageImportByName = (PIMAGE_IMPORT_BY_NAME)funcNameBuffer;

				if (
					!_stricmp(pImageImportByName->Name, szFuncName) &&
					!_stricmp((CHAR*)libNameBuffer, szLibName))
				{
					info->realFuncAddress = thunkDataIAT.u1.Function;
					info->entryAddress = ((uintptr_t)lpImageBaseAddress + pImageImportDescriptor->FirstThunk + (iteration * sizeof(PVOID)));

					/*unneeded sanity check
					uintptr_t actuallyRealFuncAddress;

					bSuccess = ReadProcessMemory
					(
						hProcess,
						(LPVOID)info->entryAddress,
						&actuallyRealFuncAddress,
						sizeof(actuallyRealFuncAddress),
						0
					);

					if (!bSuccess)
					{
						printf("ReadProcessMemory() failed (%d) at line %d\n", GetLastError(), __LINE__);
						return 0;
					}

					if (actuallyRealFuncAddress != info->realFuncAddress)
					{
						printf("Unverifiable real function address at line %d\n", GetLastError(), __LINE__);
						return 0;
					}*/

					/*DWORD oldProtect;

					bSuccess = VirtualProtectEx
					(
						hProcess,
						(LPVOID)info->entryAddress,
						sizeof(uintptr_t),
						PAGE_READWRITE,
						&oldProtect
					);

					if (!bSuccess)
					{
						printf("VirtualProtectEx() failed (%d) at line %d\n", GetLastError(), __LINE__);
						return 0;
					}

					bSuccess = WriteProcessMemory
					(
						hProcess,
						(LPVOID)info->entryAddress,
						&newEntry,
						sizeof(newEntry),
						0
					);

					if (!bSuccess)
					{
						printf("WriteProcessMemory() failed (%d) at line %d\n", GetLastError(), __LINE__);
						return 0;
					}

					bSuccess = VirtualProtectEx
					(
						hProcess,
						(LPVOID)info->entryAddress,
						sizeof(uintptr_t),
						oldProtect,
						&oldProtect
					);

					if (!bSuccess)
					{
						printf("VirtualProtectEx() failed (%d) at line %d\n", GetLastError(), __LINE__);
						return 0;
					}*/

					break;
				}
			}

			++iteration;
		}

		if (!_stricmp((CHAR*)libNameBuffer, szLibName))
			break;

		++pImageImportDescriptor;
	}

	free(buffer);

	return info;
}

HOOK_INFO* GetHookInfo(HANDLE hProcess, LPCSTR szLibName, LPCSTR szFuncName)
{
	PPEB pPEB = FindRemotePEB(hProcess);

	if (!pPEB)
	{
		printf("FindRemotePEB() failed at line %d\n", __LINE__);
		return 0;
	}

	PIMAGE_DATA_DIRECTORY pImageImportDirectory = ReadRemoteDataDirectoryRVA(hProcess, pPEB->ImageBaseAddress, IMAGE_DIRECTORY_ENTRY_IMPORT);

	if (!pImageImportDirectory)
	{
		printf("ReadRemoteDataDirectoryRVA() failed at line %d\n", __LINE__);
		return 0;
	}

	return GetHookInfo(hProcess, pImageImportDirectory, pPEB->ImageBaseAddress, szLibName, szFuncName);
}

BOOL SwapEntry(HANDLE hProcess, HOOK_INFO * pHookInfo, uintptr_t newEntry)
{
	DWORD oldProtect;

	BOOL bSuccess = VirtualProtectEx
	(
		hProcess,
		(LPVOID)pHookInfo->entryAddress,
		sizeof(uintptr_t),
		PAGE_READWRITE,
		&oldProtect
	);

	if (!bSuccess)
	{
		printf("VirtualProtectEx() failed (%d) at line %d\n", GetLastError(), __LINE__);
		return 0;
	}

	bSuccess = WriteProcessMemory
	(
		hProcess,
		(LPVOID)pHookInfo->entryAddress,
		&newEntry,
		sizeof(pHookInfo),
		0
	);

	if (!bSuccess)
	{
		printf("WriteProcessMemory() failed (%d) at line %d\n", GetLastError(), __LINE__);
		return 0;
	}

	bSuccess = VirtualProtectEx
	(
		hProcess,
		(LPVOID)pHookInfo->entryAddress,
		sizeof(uintptr_t),
		oldProtect,
		&oldProtect
	);

	if (!bSuccess)
	{
		printf("VirtualProtectEx() failed (%d) at line %d\n", GetLastError(), __LINE__);
		return 0;
	}

	return TRUE;
}
