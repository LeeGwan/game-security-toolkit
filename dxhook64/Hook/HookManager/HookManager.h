#pragma once
#include "../syscall/syscall.h"
#include <vector>
#include <memory>
// Function hooking with syscall-based memory protection
class HookManager
{
public:
	HookManager();
	~HookManager();
	// VirtualProtect via syscall (bypass user-mode hooks)
	void sys_VirtualProtect(LPVOID lpAddress, SIZE_T* dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	// Install JMP hook and return trampoline
	void* install_jmp(void* target, void* hook, size_t size);

private:
	inline_syscall syscall{};
	// Create trampoline and install hook
	uintptr_t Inlinehook(void* src, void* dest, size_t size, std::vector<byte>* ogBytes, uintptr_t* og_page_addr);

};
extern std::unique_ptr<HookManager> g_HookManager;

