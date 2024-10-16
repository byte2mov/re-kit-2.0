#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <Windows.h>
#include <Psapi.h>
#include <intrin.h>
#include <wininet.h>
#include <winhttp.h>
#include <queue>
#include <fstream>
#pragma comment(lib, "winhttp.lib")

#define STATUS_SUCCESS ((NTSTATUS)0x000000)
#define STATUS_UNSUCCESSFUL 0xC0000001L


class context {
public :
	DWORD pid;
	uintptr_t base_address;
	void* system_address;
	HMODULE ntdll;
	
	bool create_menu = false;
	bool block_threads = false;
	bool hijack_threads = false;
	bool block_exception_handler = false;
	bool log_thread_address = true;
	bool hijack_peb = true;
	uintptr_t hijacked_thread;
	std::vector<std::string> log_messages;
	std::queue<std::string> log_queue;
	std::deque<std::string> copy_queue;

	void add_log_message(const char* format, ...) {
		char buffer[256];
		va_list args;
		va_start(args, format);
		vsnprintf(buffer, sizeof(buffer), format, args);
		va_end(args);
		if (create_menu) {
			log_messages.push_back(buffer); 
		}
		else {
			log_queue.push(buffer);
		}
	}

	void process_log_queue() {
		while (!log_queue.empty()) {
			log_messages.push_back(log_queue.front());
			log_queue.pop();
		}
	}

	void save_to_disk(PVOID data, size_t size) {
		std::ofstream file("dumped_memory.bin", std::ios_base::out | std::ios_base::binary);
		file.write((char*)data, size);
		file.close();
		
	}
};

static context* ctx = new context();

typedef struct _PROCESS_MITIGATION_POLICY_DESCRIPTOR {
	ULONG Policy;
	ULONG Reserved; 

	
	struct {
		ULONG LongFlags; 
		ULONG Reserved2; 
		// 
	} ImageDirectoryAccessPolicy;
} PROCESS_MITIGATION_POLICY_DESCRIPTOR, * PPROCESS_MITIGATION_POLICY_DESCRIPTOR;

void* RtlAdjustPrivilege;
extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);