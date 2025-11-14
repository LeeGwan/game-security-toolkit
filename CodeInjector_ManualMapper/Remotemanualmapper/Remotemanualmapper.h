#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>



// Function pointer types for remote execution
using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);
using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);

// Data passed to remote shellcode
struct RemoteMappingData
{

	f_LoadLibraryA pLoadLibraryA;           
	f_GetProcAddress pGetProcAddress;       
	f_RtlAddFunctionTable pRtlAddFunctionTable; // SEH


	BYTE* pImageBase;                        


	DWORD dwEntryPoint;                     
	BYTE* pEntryPoint;

	BOOL bSEHSupport;                        // Support SEH 
	BOOL bClearHeader;                      
};

// Injection result
struct InjectionResult
{
	bool success;                           
	BYTE* remoteBaseAddress;                 
	std::string errorMessage;               
	DWORD lastError;                        

	InjectionResult()
		: success(false)
		, remoteBaseAddress(nullptr)
		, lastError(0)
	{
	}
};
// Remote manual mapper for DLL injection
class RemoteManualMapper
{
public:
	RemoteManualMapper();
	~RemoteManualMapper();
	// Inject DLL into target process
	InjectionResult InjectDll(DWORD processId,const char* dllPath,bool clearHeader = true);
	// Unmap injected DLL
	bool UnmapRemoteDll(DWORD processId, BYTE* remoteBase);

private:
	HANDLE m_hTargetProcess;

	// PE
	bool ValidatePEFile(BYTE* pSrcData);
	BYTE* LoadAndDecryptDll(const char* dllPath, SIZE_T& fileSize);

	// Memory
	BYTE* AllocateRemoteMemory(SIZE_T size);
	bool WriteRemoteMemory(BYTE* remoteAddr, void* data, SIZE_T size);
	bool ReadRemoteMemory(BYTE* remoteAddr, void* buffer, SIZE_T size);

	// DLL mapping
	bool WriteImageToRemote(BYTE* remoteBase, BYTE* localImage, SIZE_T imageSize);
	bool WriteSectionsToRemote(BYTE* remoteBase,BYTE* localImage,IMAGE_NT_HEADERS* pNtHeader);
	//get real function address
	BYTE* ResolveJumpTarget(BYTE* pStart);

	// Shellcode creation and execution
	BYTE* CreateMapperShellcode(SIZE_T& shellcodeSize);
	bool ExecuteRemoteMapper(BYTE* remoteShellcode,BYTE* remoteMappingData
	);

	// Logging
	void LogError(const char* message);
	void LogInfo(const char* message);

	// Process management
	bool OpenTargetProcess(DWORD processId);
	void CloseTargetProcess();

};
// Shellcode executed in remote process
DWORD WINAPI RemoteMapperShellcode(RemoteMappingData* pData);