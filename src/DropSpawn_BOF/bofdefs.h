#include <windows.h>
#include <fileapi.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include "ntdll.h"
#include "beacon.h"

NTSYSAPI VOID NTAPI NTDLL$RtlInitUnicodeString(PUNICODE_STRING DestinationString, PWSTR SourceString);
NTSYSAPI BOOLEAN NTAPI NTDLL$RtlDosPathNameToNtPathName_U(PCWSTR DosFileName, PUNICODE_STRING NtFileName, PWSTR* FilePart, PVOID Reserved);
NTSYSAPI NTSTATUS NTAPI NTDLL$RtlCreateProcessParameters(PRTL_USER_PROCESS_PARAMETERS* pProcessParameters, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData);
NTSYSAPI NTSTATUS NTAPI NTDLL$RtlCreateUserProcess(PUNICODE_STRING NtImagePathName, ULONG AttributesDeprecated, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PSECURITY_DESCRIPTOR ProcessSecurityDescriptor, PSECURITY_DESCRIPTOR ThreadSecurityDescriptor, HANDLE ParentProcess, BOOLEAN InheritHandles, HANDLE DebugPort, HANDLE TokenHandle, PRTL_USER_PROCESS_INFORMATION ProcessInformation);
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
NTSYSAPI NTSTATUS NTAPI NTDLL$RtlDestroyProcessParameters(PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

WINBASEAPI HANDLE WINAPI Kernel32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI BOOL WINAPI Kernel32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
WINBASEAPI BOOL WINAPI Kernel32$CloseHandle(HANDLE);
WINBASEAPI DWORD WINAPI Kernel32$GetProcessId(HANDLE Process);
WINBASEAPI DWORD WINAPI Kernel32$GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer);
WINBASEAPI DWORD WINAPI Kernel32$GetFileAttributesW(LPCWSTR lpFileName);
WINBASEAPI DWORD WINAPI Kernel32$Sleep(DWORD dwMilliseconds);
WINBASEAPI HANDLE WINAPI Kernel32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI BOOL WINAPI Kernel32$DeleteFileW(LPCWSTR lpFileName);
WINBASEAPI HANDLE WINAPI Kernel32$CreateToolhelp32Snapshot(DWORD dwFlags,DWORD th32ProcessID);
WINBASEAPI WINBOOL WINAPI Kernel32$Process32FirstW(HANDLE hSnapshot,LPPROCESSENTRY32W lppe);
WINBASEAPI WINBOOL WINAPI Kernel32$Process32NextW(HANDLE hSnapshot,LPPROCESSENTRY32W lppe);
WINBASEAPI DWORD WINAPI Kernel32$GetCurrentProcessId(VOID);
WINBASEAPI BOOL WINAPI Kernel32$ProcessIdToSessionId(DWORD dwProcessId, DWORD *pSessionId);
WINBASEAPI HANDLE WINAPI Kernel32$GetCurrentProcess();
//WINBASEAPI DWORD WINAPI Kernel32$GetLastError(VOID);

WINBASEAPI BOOL WINAPI Advapi32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINBASEAPI BOOL WINAPI Advapi32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);

WINBASEAPI PCWSTR SHLWAPI$StrStrIW(PCWSTR pszFirst, PCWSTR pscSrch);

WINBASEAPI errno_t __cdecl MSVCRT$wcscat_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource);
WINBASEAPI int __cdecl MSVCRT$swprintf_s(wchar_t *buffer, size_t sizeOfBuffer, const wchar_t *format, ...);
WINBASEAPI wchar_t* __cdecl MSVCRT$wcsrchr(const wchar_t* str, wchar_t wc);
WINBASEAPI int __cdecl MSVCRT$wcscmp(const wchar_t *string1, const wchar_t *string2);
WINBASEAPI void* __cdecl MSVCRT$memcpy( void *destination, const void* source, size_t num );
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *str);
WINBASEAPI void* __cdecl MSVCRT$memmove(void *dest, const void *src, size_t count);

#define RtlInitUnicodeString                NTDLL$RtlInitUnicodeString
#define RtlDosPathNameToNtPathName_U        NTDLL$RtlDosPathNameToNtPathName_U
#define RtlCreateProcessParameters          NTDLL$RtlCreateProcessParameters
#define RtlCreateUserProcess                NTDLL$RtlCreateUserProcess
#define NtResumeThread                      NTDLL$NtResumeThread
#define RtlDestroyProcessParameters         NTDLL$RtlDestroyProcessParameters

#define CreateFileW                         Kernel32$CreateFileW
#define WriteFile                           Kernel32$WriteFile
#define CloseHandle                         Kernel32$CloseHandle
#define GetProcessId                        Kernel32$GetProcessId
#define GetCurrentDirectoryW                Kernel32$GetCurrentDirectoryW
#define GetFileAttributesW                  Kernel32$GetFileAttributesW
#define Sleep                               Kernel32$Sleep
#define OpenProcess                         Kernel32$OpenProcess
#define DeleteFileW                         Kernel32$DeleteFileW
#define CreateToolhelp32Snapshot            Kernel32$CreateToolhelp32Snapshot
#define Process32FirstW                     Kernel32$Process32FirstW
#define Process32NextW                      Kernel32$Process32NextW
#define GetCurrentProcessId                 Kernel32$GetCurrentProcessId
#define ProcessIdToSessionId                Kernel32$ProcessIdToSessionId
#define GetCurrentProcess                   Kernel32$GetCurrentProcess
//#define GetLastError                        Kernel32$GetLastError

#define OpenProcessToken                    Advapi32$OpenProcessToken
#define GetTokenInformation                 Advapi32$GetTokenInformation

#define wcscat_s                            MSVCRT$wcscat_s
#define swprintf_s                          MSVCRT$swprintf_s
#define wcsrchr                             MSVCRT$wcsrchr
#define wcscmp                              MSVCRT$wcscmp
#define memcpy                              MSVCRT$memcpy
#define wcslen                              MSVCRT$wcslen
#define memmove                             MSVCRT$memmove

#define StrStrIW                            SHLWAPI$StrStrIW