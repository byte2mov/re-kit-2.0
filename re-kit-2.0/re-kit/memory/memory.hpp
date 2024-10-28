#pragma once
#include "../includes/includes.h"

class memory {
public :
    void set_brkp(void* address) {
        unsigned char original_byte;
        SIZE_T bytesRead;
        HANDLE hProcess = GetCurrentProcess();
        if (ReadProcessMemory(hProcess, address, &original_byte, sizeof(original_byte), &bytesRead)) {
            unsigned char breakpoint_byte = 0xCC;
            WriteProcessMemory(hProcess, address, &breakpoint_byte, sizeof(breakpoint_byte), nullptr);
        }
    }

    void restore_byte(void* address, unsigned char original_byte) {
        HANDLE hProcess = GetCurrentProcess();
        WriteProcessMemory(hProcess, address, &original_byte, sizeof(original_byte), nullptr);
    }

    auto patch_vmp_memory() -> bool {
        unsigned long old_protect = 0;
		if (!ctx->ntdll) {
			ctx->add_log_message("Failed to get ntdll.dll module handle");
		}
        ctx->add_log_message("ntdll.dll module handle: 0x%p", ctx->ntdll);
        unsigned char call = ((unsigned char*)GetProcAddress(ctx->ntdll, ("NtQuerySection")))[4] - 1;
        unsigned char restore[] = { 0x4C, 0x8B, 0xD1, 0xB8, call };
        auto nt_protect_virtual_memory = (std::uint8_t*)GetProcAddress(ctx->ntdll, "NtProtectVirtualMemory");
        if (!nt_protect_virtual_memory) {
			ctx->add_log_message("Failed to get NtProtectVirtualMemory function address");
            return false;
        }
		ctx->add_log_message("NtProtectVirtualMemory function address: 0x%p", nt_protect_virtual_memory);

        VirtualProtect(nt_protect_virtual_memory, sizeof(restore), PAGE_EXECUTE_READWRITE, &old_protect);
        memcpy(nt_protect_virtual_memory, restore, sizeof(restore));
        VirtualProtect(nt_protect_virtual_memory, sizeof(restore), old_protect, &old_protect);

		// this was taken off of  unknowncheats.me, saw it on a thread and then applied it to my project, grabbed the restore bytes from a github repo.
      //  https://github.com/BinaryFemboys/byte-patch-dll/blob/main/byte-patch-dll.cpp#L23
	}

    auto find_packer() -> std::string {

		auto dos_header = (IMAGE_DOS_HEADER*)ctx->base_address;

		auto nt_header = (IMAGE_NT_HEADERS*)((std::uint8_t*)ctx->base_address + dos_header->e_lfanew);

		auto section_header = (IMAGE_SECTION_HEADER*)((std::uint8_t*)ctx->base_address + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));
		for (int i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
			if (section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				std::string section_name((char*)(ctx->base_address + section_header[i].Name), 8);
				if (section_name == ".themida") {
					return "Packer: Themida 3.XX";
				}
                if (section_name.find(".vmp")) {
                    return "Packer: VMProtect";
                }
               
			}
		}
		return "No packer Detected";
	}


};
static memory* mem = new memory();

