#include "pch.hpp"
#include "mMap.hpp"
#include "process.hpp"
#include "helpers.hpp"

// Manual mapping

bool GetLoadedModules()
{
	DBG_OUT("Enumerating remote modules...\n");

	// Enumerating modules in target process

	DWORD ArraySz;
	HMODULE handles[1024];

	if (!EnumProcessModules(hProcess, handles, sizeof(handles), &ArraySz))
	{
		ERR_OUT("Failed to enumerate remote modules\n");
		return false;
	}

	// Creating a DLL_DATA instance for each module

	ArraySz /= sizeof(HMODULE);
	modules.reserve(ArraySz);

	for (DWORD i = 0; i < ArraySz; ++i)
	{
		char ModulePath[MAX_PATH];
		GetModuleFileNameExA(hProcess, handles[i], ModulePath, sizeof(ModulePath));

		DLL_DATA dll;
		dll.flags |= RemoteLoaded;

		std::string& DllPath = dll.DllPath;

		DllPath = ModulePath;
		dll.DllName = PathToFileName(DllPath);
		dll.pRemoteBase = handles[i];

		modules.emplace_back(dll);
	}

	DNDBG_OUT("Modules enumerated: " << ArraySz);

	return true;
}

bool RemoteMapModule(const DLL_DATA* dll)
{
	const SECTION_HEADER* section = dll->FirstSection;

	if (!WPM(hProcess, dll->pRemoteBase, dll->pLocalBase, dll->NtHeader->OptionalHeader.SizeOfHeaders))
	{
		NERR_OUT("Failed to map PE headers for: " << dll->DllPath);
		return false;
	}

	for (int i = 0; i < dll->SectionCount; ++section, ++i)
	{
		void* LocalSectionBase = reinterpret_cast<void*>(dll->LocalBase + section->PointerToRawData);
		void* RemoteSectionBase = reinterpret_cast<void*>(dll->RemoteBase + section->VirtualAddress);
		const UINT SizeOfRawData = section->SizeOfRawData;

		if (SizeOfRawData && !WPM(hProcess, RemoteSectionBase, LocalSectionBase, SizeOfRawData))
		{
			NERR_OUT("Failed to map section: " << section->Name);
			return false;
		}
	}

	DNDBG_OUT("DLL mapped: " << dll->DllName);
	return true;
}

// General use

bool GetProcessHandle(PCWSTR ProcessName)
{
	DBG_OUT("Opening process handle...\n");

	const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
	{
		CERR_OUT("CreateToolhelp32Snapshot failed!");
		return false;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	do
	{
		if (_wcsicmp(ProcessName, pe32.szExeFile) == 0)
		{
			CloseHandle(snap);

			// PROCESS_QUERY_LIMITED_INFORMATION is requested to check if the process is running under WOW64.
			// If for whatever reason you want to avoid this access right, you can remove it aswell as the WOW64 check without issue.

			constexpr DWORD dwDesiredAccess = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION;
			const HANDLE process = OpenProcess(dwDesiredAccess, false, pe32.th32ProcessID);
			if (!process)
			{
				CERR_OUT("OpenProcess failed!");
				return false;
			}

			BOOL Wow64Process;
			IsWow64Process(process, &Wow64Process);

			if (!Wow64Process)
			{
				CloseHandle(process);
				CERR_OUT("Invalid process architecture!\n");
				return false;
			}

			DBG_OUT("Success!\n\n");

			hProcess = process;
			return true;
		}

	} while (Process32Next(snap, &pe32));

	CloseHandle(snap);
	ERR_OUT("Failed to locate process!\n");
	return false;
}

bool LoadLibInject(PCWSTR DllPath)
{
	const size_t PathSize = wcslen(DllPath);

	void* DllBuffer = VirtualAllocExFill(hProcess, PathSize, PAGE_READWRITE);
	if (!DllBuffer)
	{
		CERR_OUT("VirtualAllocEx failed!");
		return false;
	}

	if (!WPM(hProcess, DllBuffer, DllPath, PathSize))
	{
		CERR_OUT("WriteProcessMemory failed!");
		return false;
	}

	const FARPROC pLoadLib = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (!pLoadLib)
	{
		CERR_OUT("GetProcAddress failed!");
		return false;
	}

	if (!CreateRemoteThreadFill(hProcess, pLoadLib, DllBuffer))
	{
		CERR_OUT("CreateRemoteThread failed!");
		return false;
	}

	return true;
}