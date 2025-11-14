#include "RemoteManualMapper/RemoteManualMapper.h"
#include <iostream>
#include <string>

std::wstring UTF8ToWString(const std::string& str)
{
	int size = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
	if (size == 0) return std::wstring();
	std::wstring wstr(size - 1, 0);
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &wstr[0], size);
	return wstr;
}
void InteractiveMode()
{
	RemoteManualMapper mapper;

	std::cout << "Remote_ManualMapper Injector" << std::endl;

	// Get target process
	DWORD targetPID = 0;
	std::cout << "Enter Process ID: ";
	std::cin >> targetPID;
	std::cin.ignore();

	// Get DLL path
	std::cout << "\nEnter DLL path: ";
	std::string dllPath;
	std::getline(std::cin, dllPath);

	// Clear PE header option
	std::cout << "\nClear PE header for stealth? (y/n): ";
	char clearHeaderChoice;
	std::cin >> clearHeaderChoice;
	std::cin.ignore();

	bool clearHeader = (clearHeaderChoice == 'y' || clearHeaderChoice == 'Y');

	// Inject
	std::cout << "\n Starting injection" << std::endl;
	InjectionResult result = mapper.InjectDll(targetPID, dllPath.c_str(), clearHeader);

	if (result.success)
	{
		std::cout << "\nDLL injected successfully!" << std::endl;
		std::cout << "Remote base address: 0x" << std::hex << (uintptr_t)result.remoteBaseAddress << std::endl;

		// Unmap option
		std::cout << "\nDo you want to unmap the DLL? (y/n): ";
		char unmapChoice;
		std::cin >> unmapChoice;

		if (unmapChoice == 'y' || unmapChoice == 'Y')
		{
			if (mapper.UnmapRemoteDll(targetPID, result.remoteBaseAddress))
			{
				std::cout << "DLL unmapped successfully!" << std::endl;
			}
			else
			{
				std::cerr << "Failed to unmap DLL!" << std::endl;
			}
		}
	}
	else
	{
		std::cerr << "\n[FAILED] Injection failed!" << std::endl;
		std::cerr << "Error: " << result.errorMessage << std::endl;
		std::cerr << "Last Error Code: 0x" << std::hex << result.lastError << std::endl;
	}

	std::cout << "\nPress Enter to exit..." << std::endl;
	std::cin.ignore();
	std::cin.get();
}

int main(int argc, char* argv[])
{


	// 관리자 권한 확인
	BOOL isAdmin = FALSE;
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION elevation;
		DWORD size;

		if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size))
		{
			isAdmin = elevation.TokenIsElevated;
		}

		CloseHandle(hToken);
	}

	if (!isAdmin)
	{
		std::cout << "[WARNING] Not running with administrator privileges!" << std::endl;
		std::cout << "          Injection may fail for protected processes." << std::endl;
		std::cout << "          Please run as administrator.\n" << std::endl;
	}
	InteractiveMode();


	return 0;
}