#include "CheckDLL.h"
#include <thread>

/**
 * @brief Entry point for the DLL monitoring module.
 * Spawns a detached background thread to continuously scan for unauthorized modules.
 */
void CheckDLL::StartCheckDLL()
{
    // Execution is detached to run independently of the main thread's lifecycle.
    std::thread(DetectDLL).detach();
}

/**
 * @brief Scans the loaded module list by traversing the Process Environment Block (PEB).
 * * This method accesses the PEB directly via the GS segment register (on x64) to retrieve 
 * the 'InMemoryOrderModuleList'. Direct PEB traversal is more stealthy and reliable 
 * than using standard Windows APIs, which can be easily hooked by malicious DLLs.
 * * @return returnCheckDLL Status indicating if a prohibited DLL was identified.
 */
returnCheckDLL CheckDLL::ScanDLL()
{
    // Access the PEB address from GS:[0x60] (specific to x64 Windows)
    PPEB peb = (PPEB)__readgsqword(0x60);

    if (!peb || !peb->Ldr) {
        return returnCheckDLL::Error;
    }

    

    // Head of the doubly linked list containing modules in the order they were loaded into memory
    LIST_ENTRY* moduleList = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* currentEntry = moduleList->Flink;

    // Iterate through the linked list until we return to the head
    while (currentEntry != moduleList)
    {
        // Resolve the actual data structure from the LIST_ENTRY pointer
        PMY_LDR_DATA_TABLE_ENTRY entry =
            CONTAINING_RECORD(currentEntry, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        // Validate the module name buffer
        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0)
        {
            std::wstring name(entry->BaseDllName.Buffer,
                entry->BaseDllName.Length / sizeof(WCHAR)); 

            /**
             * Blacklist Matching: Checks for known unauthorized modules.
             * Example: "dxhook64.dll" (commonly used for DirectX-based overlays or hooks)
             */
            if (name == L"dxhook64.dll")
            {
                return returnCheckDLL::FIND;
            }
        }

        // Advance to the next module in the list
        currentEntry = currentEntry->Flink;
    }
    
    return returnCheckDLL::NOT;
}

/**
 * @brief Background monitoring loop that periodically triggers the DLL scan.
 * * This function runs indefinitely within a dedicated thread. If an unauthorized 
 * DLL is detected, it triggers an alert and terminates the process to prevent 
 * further exploitation.
 */
void CheckDLL::DetectDLL()
{
    returnCheckDLL check;
    
    // Continuous polling loop
    while (true)
    {
        check = ScanDLL();
        
        if (check == returnCheckDLL::FIND)
        {
            // Immediate notification and process termination upon detection
            MessageBoxA(NULL, "Unauthorized DLL Injection Detected!", "Anti-Cheat Protection", MB_OK | MB_ICONERROR);
            ExitProcess(0);
        }

        /**
         * Note: In high-performance anti-cheat designs, a small Sleep() is often added 
         * to the polling loop to prevent unnecessary CPU core saturation.
         */
        Sleep(500); 
    }
}
