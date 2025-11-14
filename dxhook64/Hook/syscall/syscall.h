#pragma once
#include<Windows.h>
// Error codes
#define IS_ADDRESS_NOT_FOUND -1
#define IS_CALLBACK_KILL_FAILURE -2
#define IS_INTEGRITY_STUB_FAILURE -3
#define IS_MODULE_NOT_FOUND -4
#define IS_ALLOCATION_FAILURE -5
#define IS_INIT_NOT_APPLIED -6
#define IS_SUCCESS 0

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

inline HINSTANCE hSubsystemInstances[2];
// Direct syscall invocation without user-mode hooks
class inline_syscall
{

public:

	inline_syscall();
	void unload();
	void callback();

	void set_error(int error_code) {
		last_error = error_code;
	}

	int get_error() {
		return last_error;
	}

	bool is_init() {
		return initialized;
	}

	UCHAR* get_stub() {
		return syscall_stub;
	}

	// Invoke syscall directly with SSDT index
	template <typename returnType, typename ...args>
	returnType invoke(LPCSTR ServiceName, args... arguments);

private:
	int last_error;
	bool initialized;
	UCHAR* syscall_stub;

	typedef NTSTATUS __stdcall pNtSetInformationProcess(
		HANDLE ProcessHandle,
		PROCESS_INFORMATION_CLASS ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength
	);

	struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
	{
		ULONG Version;
		ULONG Reserved;
		PVOID Callback;
	};

};



inline inline_syscall::inline_syscall() {
	UINT i;

	initialized = 0;
	syscall_stub = 0;
	last_error = IS_INIT_NOT_APPLIED;
	// Load system modules
	hSubsystemInstances[0] = LoadLibraryA("ntdll.dll");
	hSubsystemInstances[1] = LoadLibraryA("win32u.dll");

	for (i = 0; i < sizeof hSubsystemInstances / sizeof HINSTANCE; i++)
		if (hSubsystemInstances[i] == nullptr)
		{
			last_error = IS_MODULE_NOT_FOUND;
			return;
		}

	// Allocate syscall stub (mov r10, rcx; mov eax, 0; syscall; ret)
	syscall_stub = (UCHAR*)VirtualAlloc(NULL, 21, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (syscall_stub == nullptr)
	{
		last_error = IS_CALLBACK_KILL_FAILURE;
		return;
	}

	memcpy(syscall_stub, "\x4C\x8B\xD1\xB8\x00\x00\x00\x00\x0F\x05\xC3", 11);

	last_error = IS_SUCCESS;
	initialized = 1;
}
// Disable instrumentation callback
inline void inline_syscall::callback() {



	NTSTATUS Status;
	pNtSetInformationProcess* NtSetInformationProcess;
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION SyscallCallback;



	NtSetInformationProcess = (pNtSetInformationProcess*)GetProcAddress(hSubsystemInstances[0], "NtSetInformationProcess");
	if (NtSetInformationProcess == nullptr)
	{
		inline_syscall::set_error(IS_ADDRESS_NOT_FOUND);
		return;
	}

	SyscallCallback.Reserved = 0;
	SyscallCallback.Version = 0;
	SyscallCallback.Callback = NULL;

	Status = NtSetInformationProcess(
		GetCurrentProcess(),
		(PROCESS_INFORMATION_CLASS)40,
		&SyscallCallback,
		sizeof(SyscallCallback));

	if (!NT_SUCCESS(Status))
	{
		inline_syscall::set_error(IS_CALLBACK_KILL_FAILURE);
		return;
	}


	inline_syscall::set_error(IS_SUCCESS);

}

inline VOID inline_syscall::unload() {

	if (inline_syscall::syscall_stub == nullptr)
		return;

	memset(inline_syscall::syscall_stub, 0, 21);
	VirtualFree(inline_syscall::syscall_stub, 0, MEM_RELEASE);

}

template <typename returnType, typename ...args>
inline returnType inline_syscall::invoke(LPCSTR ServiceName, args... arguments) {
	UCHAR* FunctionAddress;
	INT SystemCallIndex;

	UINT i;

	if (!inline_syscall::initialized)	
	{
		inline_syscall::set_error(IS_INIT_NOT_APPLIED);
		return IS_INIT_NOT_APPLIED;
	}

	typedef returnType __stdcall NtFunction(args...);
	NtFunction* Function = (NtFunction*)inline_syscall::syscall_stub;

	for (i = 0; i < sizeof hSubsystemInstances / sizeof(HINSTANCE); ++i)
	{

		FunctionAddress = (UCHAR*)GetProcAddress(hSubsystemInstances[i], ServiceName);

		if (FunctionAddress != nullptr)
		{

			// Verify function prologue (mov r10, rcx; mov eax, ...)
			if (*(UINT*)FunctionAddress != 0xB8D18B4C) 
			{
				inline_syscall::set_error(IS_INTEGRITY_STUB_FAILURE);
				return IS_INTEGRITY_STUB_FAILURE;
			}


			
			// NtFunc+ 0x4 = Kernel SSDT Index
		
			SystemCallIndex = (UINT)FunctionAddress[4];
			memcpy(inline_syscall::get_stub() + 0x4, &SystemCallIndex, sizeof(UINT));

			if (i == 1)
				memcpy(inline_syscall::get_stub(), FunctionAddress, 21);

			inline_syscall::set_error(IS_SUCCESS);
			return Function(arguments...);
		}


	}
	inline_syscall::set_error(IS_MODULE_NOT_FOUND);
	return IS_MODULE_NOT_FOUND;


}
