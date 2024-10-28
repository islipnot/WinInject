#include "pch.hpp"
#include "mMap.hpp"
#include "process.hpp"

HANDLE hProcess = INVALID_HANDLE_VALUE;

int wmain(int argc, PWSTR argv[])
{
	DBG_OUT("> Initializing\n\n");

	PCWSTR ProcessNameW, DllPathW;
	bool method = LOAD_LIBRARY;

	// Checking arguments

	if (argc < 3)
	{
		ERR_OUT("Invalid Arguments!\n");
		return 1;
	}
	else
	{
		ProcessNameW = argv[1];
		DllPathW = argv[2];

		if (argc > 3)
		{
			if (_wcsicmp(argv[3], L"ManualMap") == 0)
			{
				method = MANUAL_MAP;
			}
			else if (_wcsicmp(argv[3], L"LoadLibraryW") != 0)
			{
				ERR_OUT("Invalid injection method!\n");
				return 1;
			}
		}
	}

	// Opening process

	if (!GetProcessHandle(ProcessNameW)) return 1;

	// Injecting DLL

	if (method == LOAD_LIBRARY && !LoadLibInject(DllPathW))
	{
		CloseHandle(hProcess);
		ERR_OUT("LoadLibraryW injection failed\n");
		return 1;
	}
	else if (method == MANUAL_MAP)
	{
		char DllPathA[MAX_PATH + 1];
		wcstombs(DllPathA, DllPathW, MAX_PATH);

		const bool status = ManualMapDll(DllPathA);

		for (DLL_DATA& dll : modules)
		{
			if (dll.LocalBase && !(dll.flags & RedirectModule)) delete[] dll.pLocalBase;
		}
		modules.clear();

		if (!status)
		{
			CloseHandle(hProcess);
			ERR_OUT("Manual map injection failed!\n");
			return 1;
		}
	}

	CloseHandle(hProcess);
	std::cout << "DLL Successfully Injected!\n";
	return 0;
}