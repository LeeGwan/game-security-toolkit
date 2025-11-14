#pragma once
#ifdef PROTECTOR_EXPORTS
#define PROTECTOR_API __declspec(dllexport)
#else
#define PROTECTOR_API __declspec(dllimport)
#endif
// Validate return addresses in call stack
class CheckRet_Addr
{
	PROTECTOR_API static bool CheckReturnAddress(int max_depth);
};

