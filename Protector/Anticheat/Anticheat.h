#pragma once
#include <Windows.h>
#include <winternl.h>
#include <unordered_map>
#include <vector>

struct hash_struct {
    char pad1[0x68];
    uint64_t hash[4];
};
// Main anti-cheat system with memory integrity verification
class AntiCheat
{
private:

    static std::unordered_map<uintptr_t, hash_struct> hashes;
    static bool bInitialized;

    static bool IsHeapMemory(PVOID address);
    static uint64_t* CalculateSectionHash(const hash_struct* hash);
    static uint64_t* CalculateMemoryHash(uintptr_t address, size_t size = 0x1000);
    static int GetModulePageCount(HMODULE hModule);
    // Hash .text and .rdata sections
    static void InitializeHashes(HMODULE hTargetModule);
    // Check Hash
    static bool VerifyMemoryIntegrity();
    //check loop
    static void IntegrityCheckLoop();

public:
    static void Initialize(HMODULE targethModule);
};