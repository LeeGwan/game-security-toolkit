#pragma once
#include <windows.h>
#include <iostream>
#include <winternl.h>
enum class returnCheckDLL
{
    Error,
    NOT,
    FIND,
};
// Detect injected DLLs via PEB traversal
class CheckDLL
{
public:
    typedef struct _MY_LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID      DllBase;
        PVOID      EntryPoint;
        ULONG      SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        LIST_ENTRY HashLinks;
        PVOID SectionPointer;
        ULONG CheckSum;
        ULONG TimeDateStamp;
        PVOID LoadedImports;
        PVOID EntryPointActivationContext;
        PVOID PatchInformation;
    } MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;

    static void StartCheckDLL();
private:
    static returnCheckDLL ScanDLL();
    static void DetectDLL();

};

