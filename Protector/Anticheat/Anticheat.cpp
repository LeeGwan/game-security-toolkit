#include "AntiCheat.h"
#include <thread>
#include <ntstatus.h> 
#include "CheckHWBP/CheckHWBP.h"
#include"CheckSysCall/CheckSysCall.h"
#include "CheckDLL/CheckDLL.h"
#include <intrin.h>
std::unordered_map<uintptr_t, hash_struct> AntiCheat::hashes;
bool AntiCheat::bInitialized = false;

bool AntiCheat::IsHeapMemory(PVOID address)
{
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0)
		return false;

	return (mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT);
}

uint64_t* AntiCheat::CalculateSectionHash(const hash_struct* hash)
{
	static uint64_t result[4];
	memcpy(result, hash->hash, sizeof(hash->hash));
	return result;
}
// Calculate hash for memory region
uint64_t* AntiCheat::CalculateMemoryHash(uintptr_t address, size_t size)
{
	static uint64_t result[4] = { 0 };

	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi)) == 0)
		return nullptr;

	if (mbi.Protect == PAGE_NOACCESS)
		return nullptr;

	BYTE* data = (BYTE*)address;
	uint64_t hash1 = 0xcbf29ce484222325;
	uint64_t hash2 = 0x100000001b3;

	__try
	{
		for (size_t i = 0; i < size; i++)
		{
			hash1 ^= data[i];
			hash1 *= 0x100000001b3;
			hash2 += data[i];
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

int AntiCheat::GetModulePageCount(HMODULE hModule)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
	return ntHeaders->OptionalHeader.SizeOfImage / 0x1000;
}
// Hash .text (code) and .rdata (VMT) sections
void AntiCheat::InitializeHashes(HMODULE hTargetModule)
{
	//text,rdata 영역을 crc routine 생성하기전 각주소값에 해쉬화 해서 나중에 crc routine 에서 사용
	//text는 CODE 변조 확인
	//rdata 는 VMT 변조 확인
	uintptr_t moduleBase = (uintptr_t)hTargetModule;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hTargetModule;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hTargetModule + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER section = &sectionHeader[i];

		bool isText = memcmp(section->Name, ".text\0\0\0", 8) == 0;
		bool isRdata = memcmp(section->Name, ".rdata\0\0", 8) == 0;
		if (!isText && !isRdata)
			continue;

		uintptr_t sectionStart = moduleBase + section->VirtualAddress;
		DWORD sectionSize = section->Misc.VirtualSize;
		DWORD numPages = (sectionSize + 0xFFF) / 0x1000;

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
//Check ALL of Memory
bool AntiCheat::VerifyMemoryIntegrity()
{
	if (!bInitialized)
		return true;

	for (auto& [address, originalHash] : hashes)
	{
		uint64_t* currentHash = CalculateMemoryHash(address);

		if (memcmp(originalHash.hash, currentHash, sizeof(originalHash.hash)) != 0)
		{
			char buf[256];
			sprintf_s(buf, "Memory modified at: 0x%llX", address);
			MessageBoxA(NULL, buf, "Integrity Violation", MB_OK | MB_ICONERROR);
			return false;
		}
	}

	return true;
}
//CRC loop
void AntiCheat::IntegrityCheckLoop()
{
	while (true)
	{
		Sleep(10);

		if (!VerifyMemoryIntegrity())
		{
			MessageBoxA(NULL, "Memory integrity check failed!", "AntiCheat", MB_OK | MB_ICONERROR);
			ExitProcess(0);
		}
	}
}
// Initialize all anti-cheat modules
void AntiCheat::Initialize(HMODULE targethModule)
{

	std::unique_ptr<CheckHWBP> m_CheckHardwareBP = std::make_unique<CheckHWBP>();
	std::unique_ptr<CheckSysCall> m_CheckSysCall = std::make_unique<CheckSysCall>();
	std::unique_ptr<CheckDLL> m_CheckDLL = std::make_unique<CheckDLL>();
	m_CheckDLL->StartCheckDLL();
	m_CheckSysCall->StartCheckSysCall();
	m_CheckHardwareBP->Initialize_CheckHWBP();

	InitializeHashes(targethModule);

	InitializeHashes(GetModuleHandleA("Protector.dll"));

	std::thread(IntegrityCheckLoop).join();
}