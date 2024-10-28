

#include "../includes/includes.h"
#include "../menu/menu.hpp"


auto retrieve_addresses() -> void {
    ctx->pid = GetCurrentProcessId();
    ctx->base_address = (uintptr_t)GetModuleHandle(nullptr);
    ctx->system_address = GetProcAddress(GetModuleHandleA("msvcrt.dll"), "system");
    ctx->ntdll = LoadLibraryA("ntdll.dll");
    if (!ctx->ntdll) {
        ctx->add_log_message("Failed to load ntdll.dll");
    }
    RtlAdjustPrivilege = GetProcAddress(ctx->ntdll, "RtlAdjustPrivilege");
}

void counter_anti_inject()
{
    hook_function(EnumProcessModulesEx, hk_EnumProcessModulesEx)
    hook_function(Module32First, hk_Module32First);
    hook_function(SetProcessMitigationPolicy, hk_SetProcessMitigationPolicy);

    enable_hooks();
}
#include "../scanner/scanner.h"
auto security_measures() -> void {

	hook_function(RtlAdjustPrivilege, hk_RtlAdjustPrivilege); // we hook this incase malware or program tries to elevate privileges in order to BSOD.
	hook_function(ShellExecuteA, hk_ShellExecuteA); // hook this in case malware or program tries to execute a file.
   // hook_function(CreateThread, hk_CreateThread); // catch all threads
	hook_function(AddVectoredExceptionHandler, hk_AddVectoredExceptionHandler); // hooking veh breaks themida programs if you return a nullptr to the VEH handler.
    hook_function(CreateProcessA, hk_CreateProcessA);
    
    hook_function(CreateToolhelp32Snapshot, hk_CreateToolhelp32Snapshot);
    // bsod prob sub_1400182F0


	enable_hooks();
}


auto entry() -> bool {
    MH_Initialize();
	retrieve_addresses();
 //   security_measures();
	// counter_anti_inject();
    CreateThread(nullptr, 0, render, nullptr, 0, nullptr);
	return TRUE;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        return entry();
        break;
    }
    return TRUE;
}

