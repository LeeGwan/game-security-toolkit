#pragma once
#include "../FindSig/FindSig.h"
#include <cstdint>
#include "../HookManager/HookManager.h"

/**
 * @namespace ret_spoofing
 * @brief Provides mechanisms to spoof the return address on the stack to bypass stack-based detection.
 * * This technique is used to hide the actual caller from automated stack-walking by anti-cheat 
 * or EDR solutions by utilizing a 'jmp [rbx]' gadget as a proxy return address.
 */
namespace ret_spoofing
{
    // Assembly stub implemented in an external .asm file
    extern "C" void* _spoofer_ret();

    // The address of the trampoline gadget (e.g., FF 23 [jmp qword ptr [rbx]])
    inline uintptr_t trampoline_addr = 0;

    /**
     * @brief Locates a suitable trampoline gadget within the process memory or system modules.
     * Searches for the 'FF 23' (jmp [rbx]) opcode pattern.
     */
    inline void Initialize()
    {
        // First, attempt to find a gadget within the main module
        trampoline_addr = (uintptr_t)FindSig::find_pattern(nullptr, "FF 23");
        
        // Fallback: search within ntdll.dll if no gadget is found in the main module
        if (!trampoline_addr)
        {
            trampoline_addr = (uintptr_t)FindSig::find_pattern("ntdll.dll", "FF 23");
        }
    }

    /**
     * @struct CallParams
     * @brief Structure used to pass context between C++ and the assembly spoofer stub.
     */
    struct CallParams
    {
        void* trampoline;   // Address of the gadget to be used as a fake return address
        void* function;     // The actual target function to be executed
        void* rbx_backup;   // Buffer to preserve the original RBX register state
    };

    /**
     * @brief Executes a function call with a spoofed return address.
     * * @tparam Ret Return type of the target function.
     * @tparam Args Argument types for the target function.
     * @param func Pointer to the target function.
     * @param args Arguments to be passed to the target function.
     * @return Ret The result of the target function execution.
     */
    template <typename Ret, typename... Args>
    inline Ret Call(Ret(*func)(Args...), Args... args)
    {
        // Initialize parameters for the assembly stub
        CallParams params;
        params.trampoline = (void*)trampoline_addr;
        params.function = (void*)func;
        params.rbx_backup = nullptr;

        /**
         * The x64 calling convention uses RCX, RDX, R8, R9 for the first four arguments.
         * We pass 'params' as the 5th argument (via stack) to the assembly stub.
         */
        using StubFunc = Ret(*)(void*, void*, void*, void*, CallParams*, void*, Args...);
        auto stub = (StubFunc)_spoofer_ret;

        // Execute the stub call, reserving necessary shadow space and spoofing the return address
        return stub(nullptr, nullptr, nullptr, nullptr, &params, nullptr, args...);
    }
}
