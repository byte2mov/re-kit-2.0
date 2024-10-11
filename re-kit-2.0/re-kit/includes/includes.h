#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <Windows.h>
#include <Psapi.h>
#include <intrin.h>
 // 
#define STATUS_SUCCESS ((NTSTATUS)0x000000)

class context {
public :
	DWORD pid;
	uintptr_t base_address;
	void* system_address;
	HMODULE ntdll;
	bool create_menu = false;

	std::vector<std::string> log_messages;

	void add_log_message(const char* format, ...) {
		char buffer[256]; 
		va_list args;
		va_start(args, format);
		vsnprintf(buffer, sizeof(buffer), format, args);
		va_end(args);
		log_messages.push_back(buffer); 
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