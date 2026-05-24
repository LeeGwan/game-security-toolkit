#include "RemoteManualMapper.h"
#include "../Xor/Xor_File.h"
#include <Psapi.h>

#pragma comment(lib, "ntdll.lib")

// Target architecture: x64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64

/**
 * @brief Shellcode executed in the target process to perform manual mapping.
 * * This function is copied to the remote process and handles:
 * 1. Base Relocation: Adjusting absolute addresses based on the new base.
 * 2. IAT Resolution: Loading required DLLs and resolving function addresses.
 * 3. TLS Callbacks: Executing Thread Local Storage initialization.
 * 4. SEH Registration: Registering exception handlers (x64 specific).
 * 5. DllMain Execution: Invoking the entry point of the mapped DLL.
 * * @param pData Pointer to a RemoteMappingData structure containing necessary context.
 * @return DWORD TRUE if mapping is successful, FALSE otherwise.
 */
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

	/**
	 * 1. Base Relocation Logic
	 * Adjusts the memory addresses if the DLL is not loaded at its preferred Base Address.
	 */
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

	/**
	 * 2. IAT (Import Address Table) Resolution
	 * Manually resolves dependencies and populates the IAT.
	 */
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

	// 3. Execute TLS Callbacks
	if (pOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
			pBase + pOpt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);

		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	// 4. Register SEH exception handlers for x64
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

	// 5. Invoke DllMain (Entry Point)
	if (pData->dwEntryPoint)
	{
		auto DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pData->dwEntryPoint);
		if (!DllMain(pBase, DLL_PROCESS_ATTACH, nullptr))
			return FALSE;
	}

	// 6. Stealth: Clear PE Headers from memory to avoid signature scanning
	if (pData->bClearHeader)
	{
		for (DWORD i = 0; i < 0x1000; ++i)
			pBase[i] = 0;
	}

	return TRUE;
}

/**
 * @brief Marker function used to calculate the size of the shellcode.
 */
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

/**
 * @brief Validates if the provided buffer is a valid x64 PE file.
 */
bool RemoteManualMapper::ValidatePEFile(BYTE* pSrcData)
{
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
		LogError("Architecture mismatch (Requires x64)");
		return false;
	}

	return true;
}

/**
 * @brief Loads the DLL into local memory and decrypts it if encrypted.
 * * This helps bypass file-system level scans by anti-cheat solutions.
 */
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
		LogError("File too small to be a valid PE");
		file.close();
		return nullptr;
	}

	BYTE* pFileData = new BYTE[fileSize];
	file.seekg(0, std::ios::beg);
	file.read((char*)pFileData, fileSize);
	file.close();

	LogInfo("DLL file loaded into memory");

	// Bypass: Decrypt the file if it's encrypted (e.g., hidden from disk scanners)
	if (pFileData[0] != 0x4d) // 0x4d = 'M' (MZ Header start)
	{
		Xor_File C_xor;
		pFileData = C_xor.Xor_dll(pFileData, fileSize);
		LogInfo("DLL decrypted successfully");
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

/**
 * @brief Maps PE headers and sections to the target process memory.
 */
bool RemoteManualMapper::WriteImageToRemote(BYTE* remoteBase, BYTE* localImage, SIZE_T imageSize)
{
	auto pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(localImage);
	auto pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(localImage + pDosHeader->e_lfanew);

	LogInfo("Writing PE headers to remote process...");
	if (!WriteRemoteMemory(remoteBase, localImage, 0x1000))
		return false;

	LogInfo("Writing sections to remote process...");
	return WriteSectionsToRemote(remoteBase, localImage, pNtHeader);
}

/**
 * @brief Iterates through PE sections and maps them individually to the remote base.
 */
bool RemoteManualMapper::WriteSectionsToRemote(
	BYTE* remoteBase, BYTE* localImage, IMAGE_NT_HEADERS* pNtHeader)
{
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

/**
 * @brief Resolves JMP/CALL targets to extract the raw machine code of the shellcode.
 * * Necessary because compilers often generate incremental linking thunks.
 */
BYTE* RemoteManualMapper::ResolveJumpTarget(BYTE* pStart) {
	
	if (!pStart) return nullptr;

	uint8_t op = pStart[0];

	switch (op) {
	case 0xE9:  // JMP near
	case 0xE8:  // CALL
	{
		int32_t rel = *reinterpret_cast<int32_t*>(pStart + 1);
		uintptr_t target = reinterpret_cast<uintptr_t>(pStart) + 5 + static_cast<intptr_t>(rel);
		return reinterpret_cast<BYTE*>(target);
	}
	case 0xEB:  // JMP short
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

/**
 * @brief Extracts the machine code from the RemoteMapperShellcode function.
 */
BYTE* RemoteManualMapper::CreateMapperShellcode(SIZE_T& shellcodeSize)
{
	BYTE* pStart = reinterpret_cast<BYTE*>(RemoteMapperShellcode);
	BYTE* pEnd = reinterpret_cast<BYTE*>(RemoteMapperShellcode_END);

	// Bypass incremental linking thunks if present
	pStart = ResolveJumpTarget(pStart);
	pEnd = ResolveJumpTarget(pEnd);
	
	shellcodeSize = pEnd - pStart;

	if (shellcodeSize == 0 || shellcodeSize > 0x100000)
	{
		LogError("Invalid shellcode size calculation");
		return nullptr;
	}

	BYTE* pCopy = new BYTE[shellcodeSize];
	memcpy(pCopy, (BYTE*)pStart, shellcodeSize);

	// Patching potential compiler-inserted stack checks (__security_check_cookie thunks)
	if (pCopy[0x1A] == 0xE8)
	{
		memset(&pCopy[0x1A], 0x90, 5); // NOP out the call
	}
	return pCopy;
}

/**
 * @brief Spawns a remote thread to execute the mapping shellcode.
 */
bool RemoteManualMapper::ExecuteRemoteMapper(
	BYTE* remoteShellcode, BYTE* remoteMappingData)
{
	LogInfo("Spawning remote thread for shellcode execution...");
	HANDLE hThread = CreateRemoteThread(
		m_hTargetProcess, nullptr, 0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteShellcode),
		remoteMappingData, 0, nullptr);

	if (!hThread)
	{
		LogError("CreateRemoteThread failed");
		return false;
	}

	LogInfo("Waiting for mapping to complete...");
	DWORD waitResult = WaitForSingleObject(hThread, 30000);

	if (waitResult == WAIT_TIMEOUT)
	{
		LogError("Remote thread timed out (30s limit)");
		CloseHandle(hThread);
		return false;
	}

	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);
	CloseHandle(hThread);

	if (exitCode == FALSE)
	{
		LogError("Shellcode returned FALSE in target process");
		return false;
	}

	LogInfo("Injection completed successfully!");
	return true;
}

/**
 * @brief Main Entry: Orchestrates the entire manual mapping process.
 */
InjectionResult RemoteManualMapper::InjectDll(
	DWORD processId, const char* dllPath, bool clearHeader)
{
	InjectionResult result;

	std::cout << "\n========================================\n"
		<< "Remote Manual Mapper (x64)\n"
		<< "========================================\n"
		<< "Target PID: " << processId << "\n"
		<< "DLL: " << dllPath << "\n"
		<< "Clear Header: " << (clearHeader ? "Yes" : "No") << "\n"
		<< "========================================\n" << std::endl;

	if (!OpenTargetProcess(processId))
	{
		result.errorMessage = "Failed to open target process";
		return result;
	}

	SIZE_T fileSize;
	BYTE* pDllData = LoadAndDecryptDll(dllPath, fileSize);
	if (!pDllData)
	{
		result.errorMessage = "Failed to load/decrypt DLL";
		CloseTargetProcess();
		return result;
	}

	if (!ValidatePEFile(pDllData))
	{
		result.errorMessage = "Invalid PE structure";
		delete[] pDllData;
		CloseTargetProcess();
		return result;
	}

	auto pDos = reinterpret_cast<IMAGE_DOS_HEADER*>(pDllData);
	auto pNt = reinterpret_cast<IMAGE_NT_HEADERS*>(pDllData + pDos->e_lfanew);

	// 1. Allocate memory in target process for the image
	BYTE* pRemoteImage = AllocateRemoteMemory(pNt->OptionalHeader.SizeOfImage);
	if (!pRemoteImage)
	{
		result.errorMessage = "Remote allocation failed";
		delete[] pDllData;
		CloseTargetProcess();
		return result;
	}

	// 2. Map headers and sections
	if (!WriteImageToRemote(pRemoteImage, pDllData, pNt->OptionalHeader.SizeOfImage))
	{
		result.errorMessage = "Failed to write image to remote process";
		VirtualFreeEx(m_hTargetProcess, pRemoteImage, 0, MEM_RELEASE);
		delete[] pDllData;
		CloseTargetProcess();
		return result;
	}

	// 3. Prepare Mapping Context (Pointers to APIs)
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
		result.errorMessage = "Failed to write mapping data";
		VirtualFreeEx(m_hTargetProcess, pRemoteImage, 0, MEM_RELEASE);
		delete[] pDllData;
		CloseTargetProcess();
		return result;
	}

	// 4. Create and Write Shellcode
	SIZE_T shellcodeSize;
	BYTE* pShellcode = CreateMapperShellcode(shellcodeSize);
	if (!pShellcode)
	{
		result.errorMessage = "Failed to extract shellcode";
		VirtualFreeEx(m_hTargetProcess, pRemoteImage, 0, MEM_RELEASE);
		VirtualFreeEx(m_hTargetProcess, pRemoteMappingData, 0, MEM_RELEASE);
		delete[] pDllData;
		CloseTargetProcess();
		return result;
	}

	BYTE* pRemoteShellcode = AllocateRemoteMemory(shellcodeSize);
	if (!pRemoteShellcode || !WriteRemoteMemory(pRemoteShellcode, pShellcode, shellcodeSize))
	{
		result.errorMessage = "Failed to write shellcode to remote memory";
		delete[] pShellcode;
		VirtualFreeEx(m_hTargetProcess, pRemoteImage, 0, MEM_RELEASE);
		VirtualFreeEx(m_hTargetProcess, pRemoteMappingData, 0, MEM_RELEASE);
		delete[] pDllData;
		CloseTargetProcess();
		return result;
	}

	delete[] pShellcode;

	// 5. Execution Phase
	if (!ExecuteRemoteMapper(pRemoteShellcode, pRemoteMappingData))
	{
		result.errorMessage = "Shellcode execution failed";
		VirtualFreeEx(m_hTargetProcess, pRemoteImage, 0, MEM_RELEASE);
		VirtualFreeEx(m_hTargetProcess, pRemoteMappingData, 0, MEM_RELEASE);
		VirtualFreeEx(m_hTargetProcess, pRemoteShellcode, 0, MEM_RELEASE);
		delete[] pDllData;
		CloseTargetProcess();
		return result;
	}

	// Cleanup artifacts (Keep the mapped image, free the loader/shellcode)
	VirtualFreeEx(m_hTargetProcess, pRemoteShellcode, 0, MEM_RELEASE);
	VirtualFreeEx(m_hTargetProcess, pRemoteMappingData, 0, MEM_RELEASE);

	delete[] pDllData;
	CloseTargetProcess();

	result.success = true;
	result.remoteBaseAddress = pRemoteImage;

	return result;
}

/**
 * @brief Unmaps the DLL from the target process.
 */
bool RemoteManualMapper::UnmapRemoteDll(DWORD processId, BYTE* remoteBase)
{
	if (!OpenTargetProcess(processId))
		return false;

	bool success = VirtualFreeEx(m_hTargetProcess, remoteBase, 0, MEM_RELEASE);

	if (success)
		LogInfo("Target DLL successfully unmapped");
	else
		LogError("Failed to unmap DLL");

	CloseTargetProcess();
	return success;
}
