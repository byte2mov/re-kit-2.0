#pragma once
#include <d3d9.h>
#include "../includes/includes.h"
#include "../includes/imgui/imgui.h"
#include "../includes/imgui/imgui_impl_win32.h"
#include "../includes/imgui/imgui_impl_dx9.h"
#include "../memory/memory.hpp"
#include "../hooks/hooking.hpp"
#include "../scanner/scanner.h"

LPDIRECT3D9             g_pD3D = nullptr;
LPDIRECT3DDEVICE9       g_pd3dDevice = nullptr;
D3DPRESENT_PARAMETERS   g_d3dpp;
HWND                    main_hwnd = nullptr;
WNDCLASSEX              wc;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
void ResetD3DDevice()
{
    ImGui_ImplDX9_InvalidateDeviceObjects();
    const HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
    if (hr == D3DERR_INVALIDCALL)
        IM_ASSERT(0);
    ImGui_ImplDX9_CreateDeviceObjects();
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, message, wParam, lParam))
        return true;

    switch (message)
    {
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

bool CreateD3DDevice()
{
    if ((g_pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == nullptr)
        return false;

    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;
    if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, main_hwnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
        return false;

    return true;
}

void CleanupD3DDevice()
{
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
    if (g_pD3D) { g_pD3D->Release(); g_pD3D = nullptr; }
    UnregisterClass(wc.lpszClassName, wc.hInstance);
}

void CreateOverlayWindow()
{
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"re-kit 2.0", nullptr };
    wc.style = WS_EX_TOOLWINDOW;
    RegisterClassEx(&wc);
    main_hwnd = CreateWindow(wc.lpszClassName, L"re-kit 2.0", WS_POPUP, 0, 0, 5, 5, NULL, NULL, wc.hInstance, NULL);

    if (!CreateD3DDevice()) {
        CleanupD3DDevice();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return;
    }
    ShowWindow(main_hwnd, SW_HIDE);
    UpdateWindow(main_hwnd);
}


void render_menu()
{

    RECT workArea{};
    SystemParametersInfo(SPI_GETWORKAREA, 0, &workArea, 0);
    const int screenWidth = workArea.right - workArea.left;
    const int screenHeight = workArea.bottom - workArea.top;

    const ImVec2 windowSize(600, 400);  
    const ImVec2 windowPos((screenWidth - windowSize.x) / 2, (screenHeight - windowSize.y) / 4);

    ImGui::SetNextWindowPos(windowPos, ImGuiCond_Always);
    ImGui::SetNextWindowSize(windowSize, ImGuiCond_Always);


    ImGui::Begin("[ re-kit 2.0 ] menu | developer: seemo/byte2mov", nullptr,
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);


    ImGui::Text("Process ID: %d", ctx->pid);

	ImGui::Text("Base Address: 0x%p", ctx->base_address);

	ImGui::Text("System Address: 0x%p", ctx->system_address);

	ImGui::Text("Hijacked Thread Address: 0x%p", ctx->hijacked_thread);

	ImGui::Text("Packer Detected: %d", mem->find_packer().c_str());




    ImGui::Spacing();
    ImGui::Separator();  
    ImGui::Text("reverse engineering tool kit 2.0");
    ImGui::Separator();


    if (ImGui::Button("create command calls hook"))
    {
        int result = MessageBoxA(0, "Are you sure you want to hook command calls?", "re-kit 2.0", MB_YESNO | MB_ICONQUESTION);

        if (result == IDYES) {
			hook_function(CreateProcessW, hk_createprocessw);
        }
    }

    if (ImGui::Button("patch vmp memory protection")) {

		int result = MessageBoxA(0, "Are you sure you want to patch vmp memory protection?", "re-kit 2.0", MB_YESNO | MB_ICONQUESTION);
        if (result == IDYES) {
            mem->patch_vmp_memory();
        }

    }

    if (ImGui::Button("create GlobalFindAtomA hook")) {
		int result = MessageBoxA(0, "Are you sure you want to hook GlobalFindAtomA?", "re-kit 2.0", MB_YESNO | MB_ICONQUESTION);
		if (result == IDYES) {
			hook_function(GlobalFindAtomA, hk_GlobalFindAtomA);
		}
	} 

    if (ImGui::Button("create anti debugger hooks")) {


        getcontexthread_t NtGetContextThread = (getcontexthread_t)GetProcAddress(ctx->ntdll, "NtGetContextThread");
        if (!NtGetContextThread) {
            ctx->add_log_message("Failed to find NtGetContextThread");
        }

		int result = MessageBoxA(0, "Are you sure you want to hook anti debugger?", "re-kit 2.0", MB_YESNO | MB_ICONQUESTION);

		if (result == IDYES) {
			hook_function(IsDebuggerPresent, hk_IsDebuggerPresent);
			hook_function(CheckRemoteDebuggerPresent, hk_CheckRemoteDebuggerPresent);
            hook_function(DebugBreak, hk_DebugBreak);
			hook_function(NtQueryInformationProcess, hk_NtQueryInformationProcess);
            hook_function(NtSetInformationThread, hk_NtSetInformationThread);
            hook_function(CreateFileA, hk_CreateFileA);
            hook_function(NtGetContextThread, hk_GetContextThread);
        }
	}
    
    if (ImGui::Button("create anti vm hooks")) {

		int result = MessageBoxA(0, "Are you sure you want to hook anti vm?", "re-kit 2.0", MB_YESNO | MB_ICONQUESTION);
		if (result == IDYES) {
			hook_function(RegOpenKeyExA, hk_RegOpenKeyExA);
            hook_function(Process32Next, hk_Process32Next);
		}
	}

	if (ImGui::Button("create FindWindowA hook")) {
		int result = MessageBoxA(0, "Are you sure you want to hook FindWindowA?", "re-kit 2.0", MB_YESNO | MB_ICONQUESTION);
		if (result == IDYES) {
			hook_function(FindWindowA, hk_FindWindowA);
        }
    }

    if (ImGui::Button("create request hook")) {
		int result = MessageBoxA(0, "Are you sure you want to hook requests?", "re-kit 2.0", MB_YESNO | MB_ICONQUESTION);
		if (result == IDYES) {
			hook_function(WinHttpSendRequest, hk_WinHttpSendRequest);
			hook_function(WinHttpReceiveResponse, hk_WinHttpReceiveResponse);
		}
	}


    if (ImGui::Button("RunPE/Memory hook")) {

        int result = MessageBoxA(0, "Are you sure you want to dump DLLs?", "re-kit 2.0", MB_YESNO | MB_ICONQUESTION);

        if (result == IDYES) {
            hook_function(WriteProcessMemory, hk_WriteProcessMemory);
        }
    }


    if (ImGui::Button("apply hooks"))
    {
        int result = MessageBoxA(0, "Are you sure you want to apply hooks?", "re-kit 2.0", MB_YESNO | MB_ICONQUESTION);

        if (result == IDYES) {
            enable_hooks();

        }

    }

    if (ImGui::Button("VMX Dumper")) {
		int result = MessageBoxA(0, "Are you sure you want to dump VMX data?", "re-kit 2.0", MB_YESNO | MB_ICONQUESTION);
		if (result == IDYES) {

           uintptr_t scanned = scanner()->find_pattern("40 56 57 48 83").get();

		   ctx->add_log_message("vmx address: 0x%p", scanned);

           MH_CreateHook((LPVOID*)scanned, hk_sub_1CF39A7FDB0, (LPVOID*)&org_sub_1CF39A7FDB0);

		   MH_EnableHook((LPVOID*)scanned);
		}
	}

    if (ImGui::Button("Exit"))
    {
        int result = MessageBoxA(0, "Are you sure you want to exit?", "re-kit 2.0", MB_YESNO | MB_ICONQUESTION);

        if (result == IDYES) {
            TerminateProcess(GetCurrentProcess(), 0);
        }

    }

    
	ImGui::Spacing();
	ImGui::Separator();
	ImGui::Text("Sections:"); 



    ImGui::Separator();
    ImGui::Text("re-kit 2.0 log:");
    ctx->create_menu = true;
    ctx->process_log_queue();
    int log_index = 0;

    for (const auto& log : ctx->log_messages) {
        ImGui::TextUnformatted(log.c_str());

        if (ctx->copy_queue.size() <= log_index) {
            ctx->copy_queue.push_back(""); 
        }

        ImGui::SameLine();
        std::string button_id = "copy##" + std::to_string(log_index);
        if (ImGui::Button(button_id.c_str())) {
            ctx->copy_queue[log_index] = log;  
            
        
        }

        log_index++;
    }

    ImGui::Separator();
    if (!ctx->copy_queue.empty()) {
       
            std::string log_to_copy;
            size_t remove_index = -1;

            for (size_t i = 0; i < ctx->copy_queue.size(); ++i) {
                if (!ctx->copy_queue[i].empty()) {
                    log_to_copy = ctx->copy_queue[i];
                    remove_index = i;
                    break;
                }
            }

            if (!log_to_copy.empty() && remove_index != -1) {
                if (OpenClipboard(NULL)) {
                    EmptyClipboard();
                    size_t logSize = log_to_copy.size() + 1;  
                    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, logSize);

                    if (hMem) {
                        char* cptr = (char*)GlobalLock(hMem);
                        memcpy(cptr, log_to_copy.c_str(), logSize); 
                        GlobalUnlock(hMem);

                        if (SetClipboardData(CF_TEXT, hMem) == NULL) {
                            ctx->add_log_message("Failed to copy log to clipboard");
                        }
                        else {
                        //    ctx->add_log_message("Successfully copied log to clipboard");
                            ctx->copy_queue.erase(ctx->copy_queue.begin() + remove_index);
                        }
                    }
                    CloseClipboard();
                }
                else {
                    ctx->add_log_message("Failed to open clipboard");
                }
            }
    }

    ImGui::End();
}


DWORD WINAPI render([[maybe_unused]] LPVOID lpParameter)
{

    CreateOverlayWindow();

    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;


    ImFont* customFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\Segoe UI\\seguibl.ttf", 17);
    io.FontDefault = customFont;  

    ImGui::StyleColorsDark();

    ImGui_ImplWin32_Init(main_hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);

    MSG msg;
    ZeroMemory(&msg, sizeof(msg));

    while (msg.message != WM_QUIT) {

        if (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        render_menu();

        ImGui::EndFrame();
        const HRESULT Clear = g_pd3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, 0, 1.0f, 0);
        if (Clear != D3D_OK)
            throw std::runtime_error("Clear didn't return D3D_OK");

        if (g_pd3dDevice->BeginScene() >= 0)
        {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            const HRESULT EndScene = g_pd3dDevice->EndScene();
            if (EndScene != D3D_OK)
                throw std::runtime_error("EndScene didn't return D3D_OK");
        }

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        const HRESULT result = g_pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
        if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET) {
            ResetD3DDevice();
        }

    }

    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupD3DDevice();

    return 0;
}