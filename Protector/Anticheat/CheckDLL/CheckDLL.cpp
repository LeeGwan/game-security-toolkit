#include "CheckDLL.h"
#include <thread>
void CheckDLL::StartCheckDLL()
{
	std::thread(DetectDLL).detach();
}
// Scan loaded modules via PEB
returnCheckDLL CheckDLL::ScanDLL()
{
	PPEB peb = (PPEB)__readgsqword(0x60);

	if (!peb || !peb->Ldr) {
        return returnCheckDLL::Error;
	}
	LIST_ENTRY* moduleList = &peb->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* currentEntry = moduleList->Flink;
    while (currentEntry != moduleList)
    {
       
        PMY_LDR_DATA_TABLE_ENTRY entry =
            CONTAINING_RECORD(currentEntry, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0)
        {
            std::wstring name(entry->BaseDllName.Buffer,
                entry->BaseDllName.Length / sizeof(WCHAR)); 
            // Check for specific DLL (example: dxhook64.dll)
            if (name == L"dxhook64.dll")
            {
                return returnCheckDLL::FIND;
            }
        }

        currentEntry = currentEntry->Flink;
    }
    return returnCheckDLL::NOT;
}

void CheckDLL::DetectDLL()
{
    returnCheckDLL check;
    while (1)
    {
        check= ScanDLL();
        if (check == returnCheckDLL::FIND)
        {
            MessageBoxA(NULL, "Find DLL", "AntiCheat", MB_OK | MB_ICONERROR);
            ExitProcess(0);
        }
    }
	return ;
}
