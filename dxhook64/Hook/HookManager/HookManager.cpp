#include "HookManager.h"
#include "../ret_spoofing/ret_spoofing.h"

std::unique_ptr<HookManager> g_HookManager=std::make_unique<HookManager>();
HookManager::HookManager()
{
	syscall= inline_syscall{ };
}

HookManager::~HookManager()
{
}

void HookManager::sys_VirtualProtect(LPVOID lpAddress, SIZE_T* dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	PVOID baseAddress = lpAddress;
	syscall.invoke<NTSTATUS>("ZwProtectVirtualMemory", GetCurrentProcess(), &baseAddress, dwSize, flNewProtect, lpflOldProtect);
}

void* HookManager::install_jmp(void* target, void* hook, size_t size)
{
	std::vector<byte> ogBytes{ };
	uintptr_t ogPageAddr{ };


	uintptr_t retAddr = Inlinehook(target, hook, size, &ogBytes, &ogPageAddr);
	return (PVOID)retAddr;
}

uintptr_t HookManager::Inlinehook(void* src, void* dest, size_t size, std::vector<byte>* ogBytes, uintptr_t* og_page_addr)
{
	const DWORD MinLen5 = 5;  
	const DWORD MinLen14 = 14; 

	if (size < MinLen5) return NULL;




	// Allocate trampoline
	void* pTrampoline = VirtualAlloc(0, size + MinLen14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pTrampoline) return NULL;

	// Change memory protection via syscall
	DWORD dwOld = 0;
	size_t tmpsize = size;
	sys_VirtualProtect(src, &tmpsize, PAGE_EXECUTE_READWRITE, &dwOld);

	// Copy original bytes to trampoline
	memcpy(pTrampoline, src, size);

	// Add jump back to original function
	BYTE* trampolineJmp = (BYTE*)pTrampoline + size;
	trampolineJmp[0] = 0xFF;  // jmp
	trampolineJmp[1] = 0x25;  // [rip+0]
	*(DWORD*)(trampolineJmp + 2) = 0x00000000;
	*(DWORD64*)(trampolineJmp + 6) = (DWORD64)src + size;


	INT64 relativeOffset = (INT64)dest - ((INT64)src + 5);

	// Install hook: try relative JMP first
	if (relativeOffset >= INT_MIN && relativeOffset <= INT_MAX)
	{
	
		BYTE* hookJmp = (BYTE*)src;
		hookJmp[0] = 0xE9;  // jmp rel32
		*(INT32*)(hookJmp + 1) = (INT32)relativeOffset;


		for (int i = 5; i < size; i++)
			hookJmp[i] = 0x90;
	}
	else
	{
		
		BYTE* hookJmp = (BYTE*)src;
		hookJmp[0] = 0xFF;  // jmp
		hookJmp[1] = 0x25;  // [rip+0]
		*(DWORD*)(hookJmp + 2) = 0x00000000;
		*(DWORD64*)(hookJmp + 6) = (DWORD64)dest;

	
		for (int i = 14; i < size; i++)
			hookJmp[i] = 0x90;
	}

	
	tmpsize = size;
	sys_VirtualProtect(src, &tmpsize, dwOld, &dwOld);

	return (uintptr_t)pTrampoline;
}




