#pragma once
#include "../includes/minhook/MinHook.h"
#include "../includes/includes.h"
#include "../includes/imgui/imgui.h"
#include <curl/curl.h>

#define hook_function(target, replacement) \
    { \
        MH_STATUS status = MH_CreateHook((void*)(target), (replacement), (void**)&org_##target); \
        if (status != MH_OK) { \
            ctx->add_log_message("failed to hook function %p, error: %u\n", (void*)(target), status); \
        } else { \
            ctx->add_log_message("successfully created hooked function %p\n", (void*)(target)); \
        } \
    }
#define enable_hooks() \
    { \
        MH_STATUS status = MH_EnableHook(MH_ALL_HOOKS); \
        if (status != MH_OK) { \
            ctx->add_log_message("failed to enable hooks, error: %u\n", status); \
        } else { \
            ctx->add_log_message("successfully enabled all hooks\n"); \
        } \
    }




typedef int (WINAPI* original_system)(const char* lp_command);
original_system org_system = nullptr;

typedef BOOL(WINAPI* createprocessw)(
    LPCWSTR lp_application_name,
    LPWSTR lp_command_line,
    LPSECURITY_ATTRIBUTES lp_process_attributes,
    LPSECURITY_ATTRIBUTES lp_thread_attributes,
    BOOL b_inherit_handles,
    DWORD dw_creation_flags,
    LPVOID lp_environment,
    LPCWSTR lp_current_directory,
    LPSTARTUPINFOW lp_startup_info,
    LPPROCESS_INFORMATION lp_process_information
    );

createprocessw org_CreateProcessW = nullptr;

BOOL WINAPI hk_createprocessw(
    LPCWSTR lp_application_name,
    LPWSTR lp_command_line,
    LPSECURITY_ATTRIBUTES lp_process_attributes,
    LPSECURITY_ATTRIBUTES lp_thread_attributes,
    BOOL b_inherit_handles,
    DWORD dw_creation_flags,
    LPVOID lp_environment,
    LPCWSTR lp_current_directory,
    LPSTARTUPINFOW lp_startup_info,
    LPPROCESS_INFORMATION lp_process_information)
{
    MessageBoxW(0, lp_command_line, L"re-kit 2.0", MB_OK);

    return org_CreateProcessW(
        lp_application_name,
        lp_command_line,
        lp_process_attributes,
        lp_thread_attributes,
        b_inherit_handles,
        dw_creation_flags,
        lp_environment,
        lp_current_directory,
        lp_startup_info,
        lp_process_information
    );
}

typedef CURLcode(WINAPI* curl_easy_setopt_t)(CURL* curl, CURLoption option, ...);
curl_easy_setopt_t org_curl_easy_setopt = nullptr;

CURLcode hk_curl_easy_setopt(CURL* curl, CURLoption option, ...)
{
    va_list args;
    va_start(args, option);

    switch (option) {
    case CURLOPT_POSTFIELDS: {
        char* data = va_arg(args, char*);
        std::string message;

        if (data) {
            message = "curl_easy_setopt: CURLOPT_POSTFIELDS - ";
            message += data;
        }
        else {
            message = "curl_easy_setopt: CURLOPT_POSTFIELDS - None";
        }

        MessageBoxA(0, message.c_str(), "re-kit 2.0", MB_OK);
        break;
    }
    default:
        break;
    }

    va_end(args);
    return org_curl_easy_setopt(curl, option);
}



typedef ATOM(WINAPI* global_find_atom_a)(LPCSTR lp_string);
global_find_atom_a org_GlobalFindAtomA = nullptr;

ATOM hk_GlobalFindAtomA(LPCSTR lp_string)
{
	std::string message = "caught atom check: ";
	message += lp_string;

	ctx->add_log_message(message.c_str());
	return org_GlobalFindAtomA(lp_string); 
}


typedef BOOL(WINAPI* is_debugger_present_t)();

is_debugger_present_t org_IsDebuggerPresent = nullptr;

BOOL hk_IsDebuggerPresent()
{
	// print return address using _ReturnAddress() to get the return address
	void* return_address = _ReturnAddress();
	ctx->add_log_message("caught IsDebuggerPresent, resolving return as false at address: %p", return_address);
    return FALSE;
	ctx->add_log_message("caught IsDebuggerPresent, resolved.");
}


typedef HWND(WINAPI* findwindowa_t)(LPCSTR lp_class_name, LPCSTR lp_window_name);

findwindowa_t org_FindWindowA = nullptr;

std::vector<std::string> windows_found;

const std::vector<std::string> whitelisted_windows = {
    "GameWindow", // add windows here.
};
bool continue_search = true;

HWND WINAPI hk_FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName) {
 
    std::string converted_class = lpClassName;

    for (const auto& whitelisted_class : whitelisted_windows)
    {
        if (whitelisted_class == converted_class) {
            ctx->add_log_message("whitelisted window found, returning original function");
			return org_FindWindowA(lpClassName, lpWindowName);
        }
    }

    if (continue_search) {
        std::string message = "caught FindWindowA: ";
        message += lpClassName ? lpClassName : "nullptr";
        message += " - ";
        message += lpWindowName ? lpWindowName : "nullptr";

        windows_found.push_back(converted_class);

        ctx->add_log_message(message.c_str());
    }
    return nullptr;
}


typedef void(WINAPI* debugbreak_t)();

debugbreak_t org_DebugBreak = nullptr;

void hk_DebugBreak() {
	ctx->add_log_message("DebugBreak caught and stopped from execution");
}


typedef BOOL(WINAPI* check_remote_debugger_present_t)(HANDLE hProcess);

check_remote_debugger_present_t org_CheckRemoteDebuggerPresent = nullptr;

BOOL hk_CheckRemoteDebuggerPresent(HANDLE hProcess) {
	ctx->add_log_message("CheckRemoteDebuggerPresent caught and resolved value");
	return FALSE;
}

#include <winternl.h>
#include <TlHelp32.h>

typedef NTSTATUS(WINAPI* nt_query_information_process_t)(HANDLE process_handle, PROCESSINFOCLASS process_info_class, PVOID process_info, ULONG process_info_size, PULONG return_length);

nt_query_information_process_t org_NtQueryInformationProcess = nullptr;

NTSTATUS hk_NtQueryInformationProcess(HANDLE process_handle, PROCESSINFOCLASS process_info_class, PVOID process_info, ULONG process_info_size, PULONG return_length) {
	//ctx->add_log_message("NtQueryInformationProcess caught");

	NTSTATUS status = STATUS_SUCCESS;

    switch (process_info_class) {

    case ProcessDebugPort:
		*(HANDLE*)process_info = 0;
		ctx->add_log_message("ProcessDebugPort resolved to zero");
        break;
    
    case 0x1f:
        *(ULONG*)process_info = NULL;
		ctx->add_log_message("ProcessDebugFlags resolved to zero");

    case 0x1e:
        *(HANDLE*)process_info = NULL;
		ctx->add_log_message("ProcessDebugObject resolved to zero");

    default :
		status = org_NtQueryInformationProcess(process_handle, process_info_class, process_info, process_info_size, return_length);
      
    }

    if (process_info_class == ProcessBasicInformation) {
        PROCESS_BASIC_INFORMATION pbi;
        status = org_NtQueryInformationProcess(process_handle, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
        if (NT_SUCCESS(status)) { // confirm a successful return of the function
            PEB* pPeb = (PEB*)pbi.PebBaseAddress; // grab the actual PEB.
            pPeb->BeingDebugged = 0; // here we access the PEB and set this flag to 0 so we do not get flagged by PEB checks.
          
        }
    }

    return status;
	
}

typedef NTSTATUS(WINAPI* nt_set_information_thread_t)(HANDLE thread_handle, THREADINFOCLASS thread_info_class, PVOID thread_info, ULONG thread_info_size);

nt_set_information_thread_t org_NtSetInformationThread = nullptr;

NTSTATUS hk_NtSetInformationThread(HANDLE thread_handle, THREADINFOCLASS thread_info_class, PVOID thread_info, ULONG thread_info_size) {
   // ctx->add_log_message("NtSetInformationThread caught");

    NTSTATUS status = STATUS_SUCCESS;

    switch (thread_info_class) {

    case 0x11:
        ctx->add_log_message("ThreadHideFromDebugger resolved to TRUE");
        return STATUS_SUCCESS;

    

    default:
        status = org_NtSetInformationThread(thread_handle, thread_info_class, thread_info, thread_info_size);

    }
}

typedef LSTATUS(WINAPI* reg_open_key_ex_a_t)(HKEY hKey, LPCTSTR lpSubKey, REGSAM samDesired, DWORD flags, PHKEY phkResult);

reg_open_key_ex_a_t org_RegOpenKeyExA = nullptr;

LSTATUS hk_RegOpenKeyExA(HKEY hKey, LPCTSTR lpSubKey, REGSAM samDesired, DWORD flags, PHKEY phkResult) {
    return FALSE;
}


typedef BOOL(WINAPI* process32_next_t)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);

process32_next_t org_Process32Next = nullptr;

const wchar_t* whitelist_vmware[] = {
    L"vmtoolsd.exe",
    L"vmwaretray.exe",
    L"vmwareuser.exe",
    L"VGAuthService.exe",
    L"vmacthlp.exe"
};
BOOL hk_Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {

	BOOL result = org_Process32Next(hSnapshot, lppe);

    if (result) {
        for (const wchar_t*& whitelisted_process : whitelist_vmware) {
			if (_wcsicmp(lppe->szExeFile, whitelisted_process) == 0) {
            
				ctx->add_log_message("Whitelisted VMware process detection found, resolving false value");

                return FALSE;
            }
        }
    }

    // you can add any number of files but i used these ones as they are used to detect vmware.

	return result;
}



typedef HANDLE(WINAPI* create_file_a_t)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

create_file_a_t org_CreateFileA = nullptr;

HANDLE hk_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {

    const char* whitelisted_handles[] = {
        "\\\\.\\KProcessHacker3",
        "\\\\.\\HyperHideDrv"
    };
    // driver handles for anti anti debuggers and analysis tools
	for (const auto& whitelisted_handle : whitelisted_handles) {

		if (_stricmp(lpFileName, whitelisted_handle) == 0) {

			ctx->add_log_message("caught CreateFileA handle detection, resolving false value");
			return INVALID_HANDLE_VALUE;
		}
	}
}


typedef BOOL(WINAPI* getcontexthread_t)(HANDLE hThread, LPCONTEXT lpContext);

getcontexthread_t org_NtGetContextThread = nullptr;

BOOL hk_GetContextThread(HANDLE hThread, LPCONTEXT lpContext) {

    lpContext->Dr0 = 0;
    lpContext->Dr1 = 0;
    lpContext->Dr2 = 0;
    lpContext->Dr3 = 0;
    lpContext->Dr6 = 0;
    lpContext->Dr7 = 0;

	// zero all the debug registers.

	ctx->add_log_message("GetContextThread caught, zeroed all debug registers");

	return org_NtGetContextThread(hThread, lpContext);
}

typedef BOOL(WINAPI* enum_process_modules_ex_t)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);

enum_process_modules_ex_t org_EnumProcessModulesEx = nullptr;

BOOL hk_EnumProcessModulesEx(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded) {

	ctx->add_log_message("EnumProcessModulesEx caught, resolving false value");

	return FALSE;
}



typedef BOOL(WINAPI* module32_first_t)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);

module32_first_t org_Module32First = nullptr;

BOOL hk_Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme) {

	BOOL result = org_Module32First(hSnapshot, lpme);

    // check if the module being looked for is our dll, if so then return false.

	if (result) {
		if (_wcsicmp(lpme->szModule, L"re-kit-2.0.dll") == 0) {
			ctx->add_log_message("Whitelisted Module32First.dll detection found, resolving false value");
			return FALSE;
		}
        else {
            return result;
        }
	}
}

typedef NTSTATUS(WINAPI* set_process_mitigation_policy_t)(HANDLE processHandle, PROCESS_MITIGATION_POLICY policyId, PPROCESS_MITIGATION_POLICY_DESCRIPTOR policy, SIZE_T bufferLength);

set_process_mitigation_policy_t org_SetProcessMitigationPolicy = nullptr;

NTSTATUS hk_SetProcessMitigationPolicy(PROCESS_MITIGATION_POLICY MitigationPolicy, PVOID lpBuffer, SIZE_T bufferLength) {

	switch (MitigationPolicy) {

    case ProcessSignaturePolicy: 

		if (bufferLength != sizeof(PROCESS_MITIGATION_POLICY_DESCRIPTOR)) {
            return STATUS_INVALID_PARAMETER;
        }
        
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY* policy = reinterpret_cast<PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY*>(lpBuffer);

        if (policy->MicrosoftSignedOnly) { // this policy is used to defend against dll injections.
			ctx->add_log_message("SetProcessMitigationPolicy caught, MicrosoftSignedOnly resolved to False");
			return STATUS_SUCCESS;
        }

        // https://www.ired.team/offensive-security/defense-evasion/preventing-3rd-party-dlls-from-injecting-into-your-processes

    }
}


typedef NTSTATUS(WINAPI* adjust_privilege_t)(ULONG privilege, BOOLEAN enable, BOOLEAN current_thread, PBOOLEAN previous_state);

adjust_privilege_t org_RtlAdjustPrivilege = nullptr;

NTSTATUS hk_RtlAdjustPrivilege(ULONG privilege, BOOLEAN enable, BOOLEAN current_thread, PBOOLEAN previous_state) {


    // program wants to bsod using this function https://github.com/YouNeverKnow00/Anti-Debugger-Protector-Loader/blob/main/Anti%20Debuggers/protector/bsod.h
	ctx->add_log_message("possible bsod caught!, returning STATUS_INVALID_PARAMETER");

    return STATUS_INVALID_PARAMETER;

    NTSTATUS status = STATUS_SUCCESS;

    __try {
		status = org_RtlAdjustPrivilege(privilege, enable, current_thread, previous_state);
    }
	_except(EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_UNSUCCESSFUL;
    }
	if (!NT_SUCCESS(status)) {
    
    }
	return status;
}


typedef HINSTANCE(WINAPI* shell_execute_a_t)(LPCTSTR lpFile, LPCTSTR lpParameters, LPCTSTR lpDirectory, UINT nShowCmd);

shell_execute_a_t org_ShellExecuteA = nullptr;

HINSTANCE hk_ShellExecuteA(LPCTSTR lpFile, LPCTSTR lpParameters, LPCTSTR lpDirectory, UINT nShowCmd) {

	auto result = org_ShellExecuteA(lpFile, lpParameters, lpDirectory, nShowCmd);

    if (lpParameters != NULL && lstrcmp(lpParameters, L"open") == 0) {
		ctx->add_log_message("ShellExecuteA caught, opening URL or executable");
        ctx->add_log_message("attempting to open file -> ", lpDirectory);
        return (HINSTANCE)FALSE;
    }
	return result;
}

// hook createthread

typedef DWORD(WINAPI* createthread_t)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

createthread_t org_CreateThread = nullptr;

DWORD WINAPI dummy_thread([[maybe_unused]] LPVOID lpParameter) {
    while (true) {
		printf("Thread Hijacked by re-kit-2.0 - thread running\n");
    }
}

DWORD hk_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {

    if (ctx->hijack_threads) {
        ctx->hijacked_thread = ctx->base_address + 0x1520; // this offset is the function that is being threaded, you can change this to anything as long as you have address.
		if (lpStartAddress == (LPTHREAD_START_ROUTINE)ctx->hijacked_thread) { // we are targetting a specfic thread so we don't break the program in certain cases.
            org_CreateThread(lpThreadAttributes, dwStackSize, dummy_thread, lpParameter, dwCreationFlags, lpThreadId);
        }        
    }
    else if (ctx->block_threads) {
        return NULL;
    }
    else if (ctx->log_thread_address) {
        uintptr_t relative_address = (uintptr_t)lpStartAddress - ctx->base_address;
        if (relative_address <= 0xFFFFFFFF) { // ensure its a real offset
            ctx->add_log_message("Thread created at address: 0x%p", relative_address);
        }
		return org_CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }
    // in cases of dealing with ransomware, it's recommended to block threads as ransomware such as CL0P Ransomware utilize threads in order to encrypt files.
}




typedef BOOL(WINAPI* winhttpsendrequest_t)(HINTERNET hRequest, LPCTSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwFlags, DWORD dwContext);

winhttpsendrequest_t org_WinHttpSendRequest = nullptr;

BOOL hk_WinHttpSendRequest(HINTERNET hRequest, LPCTSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwFlags, DWORD dwContext) {\

  

    ctx->add_log_message("WinHttpSendRequest caught, sending HTTP request");

	return org_WinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwFlags, dwContext);
}



typedef BOOL(WINAPI* winhttpreceiveresponse_t)(HINTERNET hRequest, LPWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, LPDWORD lpdwFlags, DWORD dwContext);

winhttpreceiveresponse_t org_WinHttpReceiveResponse = nullptr;

BOOL hk_WinHttpReceiveResponse(HINTERNET hRequest, LPWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, LPDWORD lpdwFlags, DWORD dwContext) {


	ctx->add_log_message("WinHttpReceiveResponse caught, sending HTTP request");

    return org_WinHttpReceiveResponse(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, lpdwFlags, dwContext);
}

typedef PVOID(WINAPI* addvectoredexceptionhandler_t)(DWORD first, PVOID handler);

addvectoredexceptionhandler_t org_AddVectoredExceptionHandler = nullptr;

PVOID hk_AddVectoredExceptionHandler(DWORD first, PVOID handler) {

	//ctx->add_log_message("AddVectoredExceptionHandler caught, installing exception handler");

    if (ctx->block_exception_handler) { // if the program uses this themida this will break.
        if (ctx->base_address + 0x1EDA0 == (uintptr_t)handler) {
            // ctx->add_log_message("skipping veh of protection::init in the program");
             // this just skips the exception handler for the protection::init function.
             // used by some specfic programs using a popular provider.
            return nullptr;
        }
    }
    else {
        return org_AddVectoredExceptionHandler(first, handler);
    }

}


typedef BOOL(WINAPI* writeprocessmemory_t)(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);

writeprocessmemory_t org_WriteProcessMemory = nullptr;
DWORD GetParentProcessId(DWORD processId) { // sub_140019F00
    DWORD parentProcessId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == processId) {
                    parentProcessId = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return parentProcessId;
}
BOOL hk_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {

   
    ctx->add_log_message("caught memory writing, logging and dumping!");

	ctx->add_log_message("write ddress: 0x%p", lpBaseAddress);
	ctx->add_log_message("write size: 0x%p", nSize);
	ctx->add_log_message("write buffer: 0x%p", lpBuffer);

    // Get the target process ID
    DWORD processId = GetProcessId(hProcess);
    ctx->add_log_message("Target Process ID: %lu", processId);

    // Get the parent process ID
    DWORD parentProcessId = GetParentProcessId(processId);
    ctx->add_log_message("Parent Process ID: %lu", parentProcessId);

	MessageBoxA(NULL, "Memory writing detected!", "re-kit-2.0", MB_OK);

	ctx->save_to_disk(lpBuffer, nSize);


	
	return org_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

// hook CreateTool32Snapshot

typedef HANDLE(WINAPI* createtoolhelp32snapshot_t)(DWORD dwFlags, DWORD th32ProcessID);

createtoolhelp32snapshot_t org_CreateToolhelp32Snapshot = nullptr;

HANDLE hk_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {

	ctx->add_log_message("CreateToolhelp32Snapshot caught, creating snapshot");
	//MessageBoxA(NULL, "Snapshot creation detected!", "re-kit-2.0", MB_OK);
	return org_CreateToolhelp32Snapshot(dwFlags, th32ProcessID);
}

// hook char __fastcall sub_140019F00(__int64 a1)

typedef char(__fastcall* sub_140019F00_t)(__int64 a1);

sub_140019F00_t org_sub_140019F00 = nullptr;

char __fastcall hk_sub_140019F00(__int64 a1) {

	//ctx->add_log_message("sub_140019F00 caught, running function");
	MessageBoxA(NULL, "Function execution detected!", "re-kit-2.0", MB_OK);
    return TRUE;
}

// hook _BOOL8 __fastcall sub_14001B820(unsigned __int8 *a1)

typedef bool(__fastcall* sub_14001B830_t)(unsigned __int8* a1);

sub_14001B830_t org_sub_1B830 = nullptr;

bool __fastcall hk_sub_14001B830(unsigned __int8* a1) {
    return false;
}

// 0x7FDB0


// hook this char __fastcall sub_1CF39A7FDB0(__int64 a1, unsigned int a2)

typedef char(__fastcall* sub_1CF39A7FDB0_t)(__int64 a1, unsigned int a2);

sub_1CF39A7FDB0_t org_sub_1CF39A7FDB0 = nullptr;

char __fastcall hk_sub_1CF39A7FDB0(__int64 a1, unsigned int a2) {

	//ctx->add_log_message("sub_1CF39A7FDB0 caught, running function");
	MessageBoxA(NULL, "Function Injection detected!", "re-kit-2.0", MB_OK);
    // write a1 and a2 to disk

	ctx->add_log_message("write a1: 0x%p", a1);
	//ctx->add_log_message("write a2: 0x%p", a2);


	ctx->save_to_disk(&a1, sizeof(a1));
	//ctx->save_to_disk(&a2, sizeof(a2));
    return TRUE;
}

// hook CreateProcessA

typedef BOOL(WINAPI* createprocessa_t)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

createprocessa_t org_CreateProcessA = nullptr;

BOOL hk_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {

    ctx->add_log_message("CreateProcessA caught, creating process");
	MessageBoxA(NULL, "Process creation detected!", "re-kit-2.0", MB_OK);
    // output all information in messagebox
	 MessageBoxA(NULL, lpApplicationName, "Application Name", MB_OK);
	 MessageBoxA(NULL, lpCommandLine, "Command Line", MB_OK);
	 MessageBoxA(NULL, lpCurrentDirectory, "Current Directory", MB_OK);
	// MessageBoxA(NULL, lpEnvironment, "Environment Variables", MB_OK);
	 MessageBoxA(NULL, lpStartupInfo->lpDesktop, "Desktop", MB_OK);
	 MessageBoxA(NULL, lpStartupInfo->lpTitle, "Title", MB_OK);
}