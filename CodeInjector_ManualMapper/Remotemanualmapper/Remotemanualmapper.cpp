#include "RemoteManualMapper.h"
#include "../Xor/Xor_File.h"
#include <Psapi.h>

#pragma comment(lib, "ntdll.lib")

// x64 ARCH
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64

// Shellcode executed in remote process to map DLL
DWORD WINAPI RemoteMapperShellcode(RemoteMappingData* pData)
{
	if (!pData || !pData->pImageBase)
		return FALSE;

	BYTE* pBase = pData->pImageBase;

	auto pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pBase);
	if (pDosHeader->e_magic != 0x5A4D)
		return FALSE;

	auto pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + pDosHeader->e_lfanew);
	auto& pOpt = pNtHeader->OptionalHeader;

	// Resolve Relocation
	BYTE* LocationDelta = pBase - pOpt.ImageBase;
	if (LocationDelta && pOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		auto pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
			pBase + pOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		const auto pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
			reinterpret_cast<uintptr_t>(pRelocData) +
			pOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

		while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock)
		{
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			for (UINT i = 0; i < AmountOfEntries; ++i, ++pRelativeInfo)
			{
				if ((*pRelativeInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
				{
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(
						pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
				reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	// Resolve IAT
	if (pOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
			pBase + pOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pImportDescr->Name)
		{
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = pData->pLoadLibraryA(szMod);

			if (hDll)
			{
				ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(
					pBase + pImportDescr->OriginalFirstThunk);
				ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(
					pBase + pImportDescr->FirstThunk);

				if (!pThunkRef) pThunkRef = pFuncRef;

				for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
				{
					if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
					{
						*pFuncRef = (ULONG_PTR)pData->pGetProcAddress(
							hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
					}
					else
					{
						auto pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
							pBase + (*pThunkRef));
						*pFuncRef = (ULONG_PTR)pData->pGetProcAddress(hDll, pImport->Name);
					}
				}
			}
			++pImportDescr;
		}
	}

	//TLS Callbacks
	if (pOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
			pBase + pOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);

		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	// Register SEH exception handlers
	if (pData->bSEHSupport)
	{
		auto& excep = pOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size)
		{
			pData->pRtlAddFunctionTable(
				reinterpret_cast<PRUNTIME_FUNCTION>(pBase + excep.VirtualAddress),
				excep.Size / sizeof(RUNTIME_FUNCTION), (DWORD64)pBase);
		}
	}

	// Call DllMain
	if (pData->dwEntryPoint)
	{
		auto DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pData->dwEntryPoint);
		if (!DllMain(pBase, DLL_PROCESS_ATTACH, nullptr))
			return FALSE;
	}

	// Clear PE Header
	if (pData->bClearHeader)
	{
		for (DWORD i = 0; i < 0x1000; ++i)
			pBase[i] = 0;
	}

	return TRUE;
}

DWORD WINAPI RemoteMapperShellcode_END() { return 0; }


RemoteManualMapper::RemoteManualMapper() : m_hTargetProcess(nullptr) {}
RemoteManualMapper::~RemoteManualMapper() { CloseTargetProcess(); }

void RemoteManualMapper::LogError(const char* message)
{
	std::cerr << "[ERROR] " << message << " (0x" << std::hex << GetLastError() << ")" << std::endl;
}

void RemoteManualMapper::LogInfo(const char* message)
{
	std::cout << "[INFO] " << message << std::endl;
}

bool RemoteManualMapper::OpenTargetProcess(DWORD processId)
{
	m_hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (!m_hTargetProcess)
	{
		LogError("Failed to open target process");
		return false;
	}
	LogInfo("Target process opened");
	return true;
}

void RemoteManualMapper::CloseTargetProcess()
{
	if (m_hTargetProcess)
	{
		CloseHandle(m_hTargetProcess);
		m_hTargetProcess = nullptr;
	}
}

bool RemoteManualMapper::ValidatePEFile(BYTE* pSrcData)
{
	// Validate PE structure
	auto pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData);
	if (pDosHeader->e_magic != 0x5A4D)
	{
		LogError("Invalid DOS signature");
		return false;
	}

	auto pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		LogError("Invalid NT signature");
		return false;
	}

	if (pNtHeader->FileHeader.Machine != CURRENT_ARCH)
	{
		LogError("Architecture mismatch");
		return false;
	}

	return true;
}

BYTE* RemoteManualMapper::LoadAndDecryptDll(const char* dllPath, SIZE_T& fileSize)
{
	std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
	if (file.fail())
	{
		LogError("Failed to open DLL file");
		return nullptr;
	}

	fileSize = (SIZE_T)file.tellg();
	if (fileSize < 0x1000)
	{
		LogError("File too small");
		file.close();
		return nullptr;
	}

	BYTE* pFileData = new BYTE[fileSize];
	file.seekg(0, std::ios::beg);
	file.read((char*)pFileData, fileSize);
	file.close();

	LogInfo("DLL file loaded");
	//안티치트중 파일 검사 로직 우회(Bypass file scan detection)
	if (pFileData[0] != 0x4d)
	{
		Xor_File C_xor;
		pFileData = C_xor.Xor_dll(pFileData, fileSize);
		LogInfo("DLL decrypted");
	}

	return pFileData;
}

BYTE* RemoteManualMapper::AllocateRemoteMemory(SIZE_T size)
{
	BYTE* pMem = reinterpret_cast<BYTE*>(
		VirtualAllocEx(m_hTargetProcess, nullptr, size,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!pMem)
		LogError("Remote memory allocation failed");

	return pMem;
}

bool RemoteManualMapper::WriteRemoteMemory(BYTE* remoteAddr, void* data, SIZE_T size)
{
	SIZE_T written;
	if (!WriteProcessMemory(m_hTargetProcess, remoteAddr, data, size, &written))
	{
		LogError("WriteProcessMemory failed");
		return false;
	}
	return written == size;
}

bool RemoteManualMapper::ReadRemoteMemory(BYTE* remoteAddr, void* buffer, SIZE_T size)
{
	SIZE_T read;
	if (!ReadProcessMemory(m_hTargetProcess, remoteAddr, buffer, size, &read))
	{
		LogError("ReadProcessMemory failed");
		return false;
	}
	return read == size;
}

bool RemoteManualMapper::WriteImageToRemote(BYTE* remoteBase, BYTE* localImage, SIZE_T imageSize)
{
	auto pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(localImage);
	auto pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(localImage + pDosHeader->e_lfanew);

	LogInfo("Writing PE headers...");
	if (!WriteRemoteMemory(remoteBase, localImage, 0x1000))
		return false;

	LogInfo("Writing sections...");
	return WriteSectionsToRemote(remoteBase, localImage, pNtHeader);
}

bool RemoteManualMapper::WriteSectionsToRemote(
	BYTE* remoteBase, BYTE* localImage, IMAGE_NT_HEADERS* pNtHeader)
{
	// Write PE sections
	auto pSection = IMAGE_FIRST_SECTION(pNtHeader);

	for (UINT i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i, ++pSection)
	{
		if (pSection->SizeOfRawData == 0) continue;

		if (!WriteRemoteMemory(
			remoteBase + pSection->VirtualAddress,
			localImage + pSection->PointerToRawData,
			pSection->SizeOfRawData))
		{
			return false;
		}
	}
	return true;
}
//get real function address
BYTE* RemoteManualMapper::ResolveJumpTarget(BYTE* pStart) {
	
	if (!pStart) return nullptr;

	uint8_t op = pStart[0];

	switch (op) {
	case 0xE9:  // jmp near
	case 0xE8:  // call
	{
		int32_t rel = *reinterpret_cast<int32_t*>(pStart + 1);
		uintptr_t target = reinterpret_cast<uintptr_t>(pStart) + 5 + static_cast<intptr_t>(rel);
		return reinterpret_cast<BYTE*>(target);
	}
	case 0xEB:  // jmp short
	{
		int8_t rel8 = *reinterpret_cast<int8_t*>(pStart + 1);
		uintptr_t target = reinterpret_cast<uintptr_t>(pStart) + 2 + static_cast<intptr_t>(rel8);
		return reinterpret_cast<BYTE*>(target);
	}
	default:
		break;
	}

	return nullptr;
}

BYTE* RemoteManualMapper::CreateMapperShellcode(SIZE_T& shellcodeSize)
{
	// Extract shellcode from function
	BYTE* pStart = reinterpret_cast<BYTE*>(RemoteMapperShellcode);

	BYTE* pEnd = reinterpret_cast<BYTE*>(RemoteMapperShellcode_END);



	pStart = ResolveJumpTarget(pStart);

	pEnd = ResolveJumpTarget(pEnd);
	shellcodeSize = pEnd - pStart;

	if (shellcodeSize == 0 || shellcodeSize > 0x100000)
	{
		LogError("Invalid shellcode size");
		return nullptr;
	}

	std::cout << "Shellcode size: " << shellcodeSize << " bytes" << std::endl;

	BYTE* pCopy = new BYTE[shellcodeSize];
	memcpy(pCopy, (BYTE*)pStart, shellcodeSize);

	if (pCopy[0x1A] == 0xE8)
	{
		memset(&pCopy[0x1A], 0x90, 5);
	}
	return pCopy;
}

bool RemoteManualMapper::ExecuteRemoteMapper(
	BYTE* remoteShellcode, BYTE* remoteMappingData)
{
	// CreateRemoteThread를 호출하여 대상 프로세스에 원격 스레드를 생성하고,
	// remoteShellcode(원격 메모리 주소)를 시작 루틴으로 실행하며 remoteMappingData를 인자로 전달한다.
	LogInfo("Executing remote mapper");
	HANDLE hThread = CreateRemoteThread(
		m_hTargetProcess, nullptr, 0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteShellcode),
		remoteMappingData, 0, nullptr);

	if (!hThread)
	{
		LogError("CreateRemoteThread failed");
		return false;
	}

	LogInfo("Waiting for completion...");
	DWORD waitResult = WaitForSingleObject(hThread, 30000);

	if (waitResult == WAIT_TIMEOUT)
	{
		LogError("Remote thread timed out");
		CloseHandle(hThread);
		return false;
	}

	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);
	CloseHandle(hThread);

	if (exitCode == FALSE)
	{
		LogError("Remote mapper returned FALSE");
		return false;
	}

	LogInfo("Remote mapper executed successfully!");
	return true;
}

InjectionResult RemoteManualMapper::InjectDll(
	DWORD processId, const char* dllPath, bool clearHeader)
{
	InjectionResult result;

	std::cout << "\n========================================\n"
		<< "Remote Manual Mapper\n"
		<< "========================================\n"
		<< "Target PID: " << processId << "\n"
		<< "DLL: " << dllPath << "\n"
		<< "Clear Header: " << (clearHeader ? "Yes" : "No") << "\n"
		<< "========================================\n" << std::endl;

	if (!OpenTargetProcess(processId))
	{
		result.errorMessage = "Failed to open process";
		return result;
	}

	SIZE_T fileSize;
	// Load and decrypt DLL
	BYTE* pDllData = LoadAndDecryptDll(dllPath, fileSize);
	if (!pDllData)
	{
		result.errorMessage = "Failed to load DLL";
		CloseTargetProcess();
		return result;
	}
	// Validate PE structure
	if (!ValidatePEFile(pDllData))
	{
		result.errorMessage = "PE validation failed";
		delete[] pDllData;
		CloseTargetProcess();
		return result;
	}

	auto pDos = reinterpret_cast<IMAGE_DOS_HEADER*>(pDllData);
	auto pNt = reinterpret_cast<IMAGE_NT_HEADERS*>(pDllData + pDos->e_lfanew);
	// Allocate memory in target process
	BYTE* pRemoteImage = AllocateRemoteMemory(pNt->OptionalHeader.SizeOfImage);
	if (!pRemoteImage)
	{
		result.errorMessage = "Allocation failed";
		delete[] pDllData;
		CloseTargetProcess();
		return result;
	}
	// Write PE to target process
	if (!WriteImageToRemote(pRemoteImage, pDllData, pNt->OptionalHeader.SizeOfImage))
	{
		result.errorMessage = "Write failed";
		VirtualFreeEx(m_hTargetProcess, pRemoteImage, 0, MEM_RELEASE);
		delete[] pDllData;
		CloseTargetProcess();
		return result;
	}
	// Prepare mapping data
	RemoteMappingData mappingData = { 0 };
	HMODULE hK32 = GetModuleHandleA("kernel32.dll");
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

	mappingData.pLoadLibraryA = (f_LoadLibraryA)GetProcAddress(hK32, "LoadLibraryA");
	mappingData.pGetProcAddress = (f_GetProcAddress)GetProcAddress(hK32, "GetProcAddress");
	mappingData.pRtlAddFunctionTable = (f_RtlAddFunctionTable)GetProcAddress(hNtdll, "RtlAddFunctionTable");
	mappingData.pImageBase = pRemoteImage;
	mappingData.dwEntryPoint = pNt->OptionalHeader.AddressOfEntryPoint;
	mappingData.bSEHSupport = TRUE;
	mappingData.bClearHeader = clearHeader;

	BYTE* pRemoteMappingData = AllocateRemoteMemory(sizeof(RemoteMappingData));
	if (!pRemoteMappingData || !WriteRemoteMemory(pRemoteMappingData, &mappingData, sizeof(RemoteMappingData)))
	{
		result.errorMessage = "Mapping data failed";
		VirtualFreeEx(m_hTargetProcess, pRemoteImage, 0, MEM_RELEASE);
		delete[] pDllData;
		CloseTargetProcess();
		return result;
	}
	// Create and write shellcode
	SIZE_T shellcodeSize;
	BYTE* pShellcode = CreateMapperShellcode(shellcodeSize);
	if (!pShellcode)
	{
		result.errorMessage = "Shellcode failed";
		VirtualFreeEx(m_hTargetProcess, pRemoteImage, 0, MEM_RELEASE);
		VirtualFreeEx(m_hTargetProcess, pRemoteMappingData, 0, MEM_RELEASE);
		delete[] pDllData;
		CloseTargetProcess();
		return result;
	}

	BYTE* pRemoteShellcode = AllocateRemoteMemory(shellcodeSize);
	if (!pRemoteShellcode || !WriteRemoteMemory(pRemoteShellcode, pShellcode, shellcodeSize))
	{
		result.errorMessage = "Shellcode write failed";
		delete[] pShellcode;
		VirtualFreeEx(m_hTargetProcess, pRemoteImage, 0, MEM_RELEASE);
		VirtualFreeEx(m_hTargetProcess, pRemoteMappingData, 0, MEM_RELEASE);
		delete[] pDllData;
		CloseTargetProcess();
		return result;
	}

	delete[] pShellcode;
	// Execute injection
	if (!ExecuteRemoteMapper(pRemoteShellcode, pRemoteMappingData))
	{
		result.errorMessage = "Execution failed";
		VirtualFreeEx(m_hTargetProcess, pRemoteImage, 0, MEM_RELEASE);
		VirtualFreeEx(m_hTargetProcess, pRemoteMappingData, 0, MEM_RELEASE);
		VirtualFreeEx(m_hTargetProcess, pRemoteShellcode, 0, MEM_RELEASE);
		delete[] pDllData;
		CloseTargetProcess();
		return result;
	}

	VirtualFreeEx(m_hTargetProcess, pRemoteShellcode, 0, MEM_RELEASE);
	VirtualFreeEx(m_hTargetProcess, pRemoteMappingData, 0, MEM_RELEASE);

	delete[] pDllData;
	CloseTargetProcess();

	result.success = true;
	result.remoteBaseAddress = pRemoteImage;

	std::cout << "\n========================================\n"
		<< "Injection Successful!\n"
		<< "Base: 0x" << std::hex << (uintptr_t)pRemoteImage << "\n"
		<< "========================================\n" << std::endl;

	return result;
}

bool RemoteManualMapper::UnmapRemoteDll(DWORD processId, BYTE* remoteBase)
{
	if (!OpenTargetProcess(processId))
		return false;

	bool success = VirtualFreeEx(m_hTargetProcess, remoteBase, 0, MEM_RELEASE);

	if (success)
		LogInfo("DLL unmapped");
	else
		LogError("Unmap failed");

	CloseTargetProcess();
	return success;
}