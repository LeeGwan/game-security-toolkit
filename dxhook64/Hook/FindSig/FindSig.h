#pragma once
#include <cstdint>
#include <type_traits>
#include <Windows.h>
#include <vector>
namespace FindSig
{
    inline uintptr_t find_pattern(const char* szModule, const char* signature)
	{
		HANDLE module = GetModuleHandleA(szModule);
		// Convert string pattern to byte array
		static auto patternToByte = [](const char* pattern) {
			auto bytes = std::vector<int>{};
			auto start = const_cast<char*>(pattern);
			auto end = const_cast<char*>(pattern) + strlen(pattern);

			for (auto current = start; current < end; ++current) {
				if (*current == '?') {
					++current;
					if (*current == '?')
						++current;
					bytes.push_back(-1);
				}
				else {
					bytes.push_back(strtoul(current, &current, 16));
				}
			}
			return bytes;
			};
		// Get module size
		const auto dosHeader = (PIMAGE_DOS_HEADER)module;
		const auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);

		const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
		auto patternBytes = patternToByte(signature);
		const auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

		const auto s = patternBytes.size();
		const auto d = patternBytes.data();
		// Scan memory for pattern
		for (auto i = 0ul; i < sizeOfImage - s; ++i)
		{
			bool found = true;
			for (auto j = 0ul; j < s; ++j)
			{
				if (scanBytes[i + j] != d[j] && d[j] != -1)
				{
					found = false;
					break;
				}
			}
			if (found) { return reinterpret_cast<uintptr_t>(&scanBytes[i]); }
		}
		return 0;
	}

    
}
