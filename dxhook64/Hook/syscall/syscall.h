#pragma once
#include <Windows.h>

/**
 * @enum ERROR_CODES
 * @brief Internal status codes for inline syscall operations.
 */
#define IS_ADDRESS_NOT_FOUND -1
#define IS_CALLBACK_KILL_FAILURE -2
#define IS_INTEGRITY_STUB_FAILURE -3
#define IS_MODULE_NOT_FOUND -4
#define IS_ALLOCATION_FAILURE -5
#define IS_INIT_NOT_APPLIED -6
#define IS_SUCCESS 0

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// Global handles for subsystem modules (ntdll and win32u)
inline HINSTANCE hSubsystemInstances[2];

/**
 * @class inline_syscall
 * @brief Provides functionality to invoke system calls directly by extracting SSDT indices 
 * at runtime, effectively bypassing User-Mode hooks (inline/IAT hooks).
 */
class inline_syscall
{
public:
    inline_syscall();
    void unload();
    void callback();

    void set_error(int error_code) { last_error = error_code; }
    int get_error() { return last_error; }
    bool is_init() { return initialized; }
    UCHAR* get_stub() { return syscall_stub; }

    /**
     * @brief Dynamically extracts the SSDT index of a given service and invokes it directly.
     * @param ServiceName The name of the NT/Win32k function (e.g., "NtOpenProcess").
     * @param arguments Variadic arguments to pass to the system call.
     */
    template <typename returnType, typename ...args>
    returnType invoke(LPCSTR ServiceName, args... arguments);

private:
    int last_error;
    bool initialized;
    UCHAR* syscall_stub; // Executable buffer for the 'syscall' instruction stub

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

/**
 * @brief Constructor: Loads required subsystems and prepares the shellcode stub.
 * Stub logic: mov r10, rcx; mov eax, [index]; syscall; ret
 */
inline inline_syscall::inline_syscall() {
    UINT i;
    initialized = 0;
    syscall_stub = 0;
    last_error = IS_INIT_NOT_APPLIED;

    // Resolve base modules for NT and GUI subsystems
    hSubsystemInstances[0] = LoadLibraryA("ntdll.dll");
    hSubsystemInstances[1] = LoadLibraryA("win32u.dll");

    for (i = 0; i < sizeof hSubsystemInstances / sizeof HINSTANCE; i++)
        if (hSubsystemInstances[i] == nullptr) {
            last_error = IS_MODULE_NOT_FOUND;
            return;
        }

    // Allocate executable memory for the syscall stub
    syscall_stub = (UCHAR*)VirtualAlloc(NULL, 21, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (syscall_stub == nullptr) {
        last_error = IS_CALLBACK_KILL_FAILURE;
        return;
    }

    // Initialize stub with x64 syscall prologue
    // \x4C\x8B\xD1 -> mov r10, rcx
    // \xB8\x00\x00\x00\x00 -> mov eax, 0 (Index placeholder)
    // \x0F\x05 -> syscall
    // \xC3 -> ret
    memcpy(syscall_stub, "\x4C\x8B\xD1\xB8\x00\x00\x00\x00\x0F\x05\xC3", 11);

    last_error = IS_SUCCESS;
    initialized = 1;
}

/**
 * @brief Disables the ProcessInstrumentationCallback to prevent EDR/Anti-Cheat
 * from monitoring system call transitions via callbacks.
 */
inline void inline_syscall::callback() {
    NTSTATUS Status;
    pNtSetInformationProcess* NtSetInformationProcess;
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION SyscallCallback;

    NtSetInformationProcess = (pNtSetInformationProcess*)GetProcAddress(hSubsystemInstances[0], "NtSetInformationProcess");
    if (NtSetInformationProcess == nullptr) {
        inline_syscall::set_error(IS_ADDRESS_NOT_FOUND);
        return;
    }

    // Nullifying the callback to disable instrumentation (Information Class 40)
    SyscallCallback.Reserved = 0;
    SyscallCallback.Version = 0;
    SyscallCallback.Callback = NULL;

    Status = NtSetInformationProcess(
        GetCurrentProcess(),
        (PROCESS_INFORMATION_CLASS)40,
        &SyscallCallback,
        sizeof(SyscallCallback));

    if (!NT_SUCCESS(Status)) {
        inline_syscall::set_error(IS_CALLBACK_KILL_FAILURE);
        return;
    }

    inline_syscall::set_error(IS_SUCCESS);
}

inline VOID inline_syscall::unload() {
    if (inline_syscall::syscall_stub == nullptr) return;
    memset(inline_syscall::syscall_stub, 0, 21);
    VirtualFree(inline_syscall::syscall_stub, 0, MEM_RELEASE);
}

/**
 * @brief Core invocation logic: Extracts the SSDT index and executes the direct syscall.
 */
template <typename returnType, typename ...args>
inline returnType inline_syscall::invoke(LPCSTR ServiceName, args... arguments) {
    UCHAR* FunctionAddress;
    INT SystemCallIndex;
    UINT i;

    if (!inline_syscall::initialized) {
        inline_syscall::set_error(IS_INIT_NOT_APPLIED);
        return (returnType)IS_INIT_NOT_APPLIED;
    }

    typedef returnType __stdcall NtFunction(args...);
    NtFunction* Function = (NtFunction*)inline_syscall::syscall_stub;

    for (i = 0; i < sizeof hSubsystemInstances / sizeof(HINSTANCE); ++i) {
        FunctionAddress = (UCHAR*)GetProcAddress(hSubsystemInstances[i], ServiceName);
        if (FunctionAddress != nullptr) {
            // Integrity Check: Verify if the function prologue is intact (not hooked)
            // 0xB8D18B4C corresponds to 'mov r10, rcx; mov eax, ...'
            if (*(UINT*)FunctionAddress != 0xB8D18B4C) {
                inline_syscall::set_error(IS_INTEGRITY_STUB_FAILURE);
                return (returnType)IS_INTEGRITY_STUB_FAILURE;
            }

            // Extract the SSDT index from the 5th byte of the function stub
            SystemCallIndex = (UINT)FunctionAddress[4];
            memcpy(inline_syscall::get_stub() + 0x4, &SystemCallIndex, sizeof(UINT));

            // For win32u.dll (i == 1), full stub replication might be required
            if (i == 1) memcpy(inline_syscall::get_stub(), FunctionAddress, 21);

            inline_syscall::set_error(IS_SUCCESS);
            return Function(arguments...);
        }
    }
    inline_syscall::set_error(IS_MODULE_NOT_FOUND);
    return (returnType)IS_MODULE_NOT_FOUND;
}
