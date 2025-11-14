#pragma once
typedef unsigned char       BYTE;
typedef unsigned __int64 ULONG_PTR, * PULONG_PTR;
typedef ULONG_PTR SIZE_T, * PSIZE_T;
// Detect inline syscall stubs in memory
class CheckSysCall
{
public:
	static void StartCheckSysCall();
private:
	static void DetectInlineSyscall();
	static bool ScanMemoryForSyscallStub();
	static bool ContainsSyscallInstruction(BYTE* memory, SIZE_T size);
};

