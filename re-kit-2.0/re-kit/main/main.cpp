

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
}

void counter_anti_inject()
{
    hook_function(EnumProcessModulesEx, hk_EnumProcessModulesEx)
    hook_function(Module32First, hk_Module32First);

    enable_hooks();
}
auto entry() -> bool {
    MH_Initialize();
	retrieve_addresses();
	counter_anti_inject();
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

