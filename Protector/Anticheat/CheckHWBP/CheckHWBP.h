#pragma once
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
enum class returns
{
    Error,
    NOT,
    FIND,
};
// Detect hardware breakpoints
class CheckHWBP
{
public:
    static void Initialize_CheckHWBP();
private:
    static returns CheckAllThreads(DWORD processId);
    static void StartCheckHWBP();
 
};

