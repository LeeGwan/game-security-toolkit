#pragma once
#include "../FindSig/FindSig.h"
#include <cstdint>
#include "../HookManager/HookManager.h"
// Return address spoofing to hide call stack
namespace ret_spoofing
{
    extern "C" void* _spoofer_ret();

    inline uintptr_t trampoline_addr = 0;

    // Find trampoline gadget (jmp [rbx] = FF 23)
    inline void Initialize()
    {
    
        trampoline_addr = (uintptr_t)FindSig::find_pattern(nullptr,"FF 23");
        
        if (!trampoline_addr)
        {
            trampoline_addr = (uintptr_t)FindSig::find_pattern("ntdll.dll", "FF 23");
        }
    }

    
    struct CallParams
    {
        void* trampoline;   // Fake return address
        void* function;     // Target function
        void* rbx_backup;   // RBX register backup
    };

    // Call function with spoofed return address
    template <typename Ret, typename... Args>
    inline Ret Call(Ret(*func)(Args...), Args... args)
    {
       
        // 파라미터 설정
        CallParams params;
        params.trampoline = (void*)trampoline_addr;
        params.function = (void*)func;
        params.rbx_backup = nullptr;

        // 윈도우 함수 콜방식
        // rcx, rdx, r8, r9, [rsp+32], [rsp+40], ...

        using StubFunc = Ret(*)(void*, void*, void*, void*, CallParams*, void*, Args...);
        auto stub = (StubFunc)_spoofer_ret;

    
        return stub(nullptr, nullptr, nullptr, nullptr, &params, nullptr, args...);
    }
}

