#include "AntiCheat.h"
#include <thread>
#include <ntstatus.h> 
#include "CheckHWBP/CheckHWBP.h"
#include "CheckSysCall/CheckSysCall.h"
#include "CheckDLL/CheckDLL.h"
#include <intrin.h>

// Static member initialization
std::unordered_map<uintptr_t, hash_struct> AntiCheat::hashes;
bool AntiCheat::bInitialized = false;

/**
 * @brief Checks if a memory address belongs to the Heap (Private/Commit).
 * @param address The memory address to verify.
 * @return bool True if it is heap memory.
 */
bool AntiCheat::IsHeapMemory(PVOID address)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0)
        return false;

    return (mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT);
}

/**
 * @brief Simple helper to retrieve the pre-calculated hash from a hash_struct.
 */
uint64_t* AntiCheat::CalculateSectionHash(const hash_struct* hash)
{
    static uint64_t result[4];
    memcpy(result, hash->hash, sizeof(hash->hash));
    return result;
}

/**
 * @brief Calculates a 256-bit custom hash for a specific memory region.
 * Uses a FNV-1a inspired XOR-Multiply-Shift algorithm for fast and reliable integrity verification.
 * @param address Starting address of the memory region.
 * @param size Size of the region (defaults to PAGE_SIZE/0x1000).
 * @return uint64_t* Pointer to a static array containing the 4-part hash.
 */
uint64_t* AntiCheat::CalculateMemoryHash(uintptr_t address, size_t size)
{
    static uint64_t result[4] = { 0 };

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi)) == 0)
        return nullptr;

    // Skip inaccessible pages to prevent access violation crashes
    if (mbi.Protect == PAGE_NOACCESS)
        return nullptr;

    BYTE* data = (BYTE*)address;
    uint64_t hash1 = 0xcbf29ce484222325; // FNV_offset_basis
    uint64_t hash2 = 0x100000001b3;      // FNV_prime

    __try
    {
        for (size_t i = 0; i < size; i++)
        {
            hash1 ^= data[i];
            hash1 *= 0x100000001b3;
            hash2 += data[i];
            // Rotate left 5 bits to add non-linearity
            hash2 = (hash2 << 5) | (hash2 >> 59);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return nullptr;
    }

    result[0] = hash1;
    result[1] = hash2;
    result[2] = hash1 ^ hash2;
    result[3] = hash1 + hash2;

    return result;
}

/**
 * @brief Calculates the number of memory pages a module occupies.
 */
int AntiCheat::GetModulePageCount(HMODULE hModule)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    return ntHeaders->OptionalHeader.SizeOfImage / 0x1000;
}

/**
 * @brief Snapshots the original hashes of .text (Code) and .rdata (Read-only Data/VMT) sections.
 * These hashes serve as the baseline for runtime integrity verification.
 * @param hTargetModule The handle of the module to monitor.
 */
void AntiCheat::InitializeHashes(HMODULE hTargetModule)
{
    uintptr_t moduleBase = (uintptr_t)hTargetModule;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hTargetModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hTargetModule + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER section = &sectionHeader[i];

        // Target critical sections: .text for code integrity, .rdata for VMT integrity
        bool isText = memcmp(section->Name, ".text\0\0\0", 8) == 0;
        bool isRdata = memcmp(section->Name, ".rdata\0\0", 8) == 0;
        
        if (!isText && !isRdata)
            continue;

        uintptr_t sectionStart = moduleBase + section->VirtualAddress;
        DWORD sectionSize = section->Misc.VirtualSize;
        DWORD numPages = (sectionSize + 0xFFF) / 0x1000;

        // Hash each page individually to pinpoint the exact location of modification
        for (DWORD page = 0; page < numPages; page++)
        {
            uintptr_t pageAddress = sectionStart + (page * 0x1000);

            uint64_t* currentHash = CalculateMemoryHash(pageAddress);
            if (currentHash)
            {
                hash_struct hashData = { 0 };
                memcpy(hashData.hash, currentHash, sizeof(hashData.hash));

                hashes[pageAddress] = hashData;
            }
        }
    }

    bInitialized = true;
}

/**
 * @brief Iterates through saved hashes and compares them with current memory state.
 * @return bool False if any modification (hook, patch, VMT swap) is detected.
 */
bool AntiCheat::VerifyMemoryIntegrity()
{
    if (!bInitialized)
        return true;

    for (auto& [address, originalHash] : hashes)
    {
        uint64_t* currentHash = CalculateMemoryHash(address);

        if (memcmp(originalHash.hash, currentHash, sizeof(originalHash.hash)) != 0)
        {
            // Report integrity violation with the specific address
            char buf[256];
            sprintf_s(buf, "Memory modification detected at: 0x%llX", address);
            MessageBoxA(NULL, buf, "Security Violation", MB_OK | MB_ICONERROR);
            return false;
        }
    }

    return true;
}

/**
 * @brief Background monitoring thread that periodically verifies memory integrity.
 */
void AntiCheat::IntegrityCheckLoop()
{
    while (true)
    {
        // Polling interval to balance CPU usage and detection speed
        Sleep(10);

        if (!VerifyMemoryIntegrity())
        {
            // Immediate termination upon detection to prevent further exploitation
            ExitProcess(0);
        }
    }
}

/**
 * @brief Orchestrates the initialization of all anti-cheat detection modules.
 * @param targethModule The main game module handle to protect.
 */
void AntiCheat::Initialize(HMODULE targethModule)
{
    // Initialize specialized detection modules via smart pointers
    std::unique_ptr<CheckHWBP> m_CheckHardwareBP = std::make_unique<CheckHWBP>();
    std::unique_ptr<CheckSysCall> m_CheckSysCall = std::make_unique<CheckSysCall>();
    std::unique_ptr<CheckDLL> m_CheckDLL = std::make_unique<CheckDLL>();

    // Start background checks for illegal DLLs, Syscall hooks, and Hardware Breakpoints
    m_CheckDLL->StartCheckDLL();
    m_CheckSysCall->StartCheckSysCall();
    m_CheckHardwareBP->Initialize_CheckHWBP();

    // Baseline hashing for the game module and the protector itself
    InitializeHashes(targethModule);
    InitializeHashes(GetModuleHandleA("Protector.dll"));

    // Enter the continuous monitoring loop
    std::thread(IntegrityCheckLoop).join();
}
