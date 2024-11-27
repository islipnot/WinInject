#pragma warning(disable: 6387)

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

bool RemoteMapModule(DLL_DATA* dll)
{
	const SECTION_HEADER* section = dll->FirstSection;

	if (!WPM(dll->pRemoteBase, dll->pLocalBase, dll->NtHeader->OptionalHeader.SizeOfHeaders))
	{
		NERR_OUT("Failed to map PE headers for: " << dll->DllPath);
		return false;
	}

	for (UINT i = 0; i < dll->SectionCount; ++section, ++i)
	{
		void* LocalSectionBase = reinterpret_cast<void*>(dll->LocalBase + section->PointerToRawData);
		void* RemoteSectionBase = reinterpret_cast<void*>(dll->RemoteBase + section->VirtualAddress);
		const UINT SizeOfRawData = section->SizeOfRawData;

		if (SizeOfRawData && !WPM(RemoteSectionBase, LocalSectionBase, SizeOfRawData))
		{
			NERR_OUT("Failed to map section: " << section->Name);
			return false;
		}
	}

	dll->flags |= ManualMapped;

	DNDBG_OUT("DLL mapped: " << dll->DllName);
	return true;
}

bool RunDllMain(DLL_DATA& dll)
{
	DWORD EntryPoint = dll.NtHeader->OptionalHeader.AddressOfEntryPoint;
	if (!EntryPoint) return true;

	static BYTE shellcode[] =
	{
		0xE8, 0, 0, 0, 0, // call TlsAlloc
		0xB9, 0, 0, 0, 0, // mov ecx, AddressOfIndex
		0x89, 0x01,       // mov [ecx], eax
		0x6A, 0x00,       // push 0 (lpvReserved)
		0x6A, 0x01,       // push 1 (fdwReason / DLL_PROCESS_ATTACH)
		0x68, 0, 0, 0, 0, // push hinstDLL
		0xE8, 0, 0, 0, 0, // call DllMain
		0xC2, 0x04, 0x00, // ret 4
	};

	// Allocating memory for shellcode

	static void* ShellAddress = VirtualAllocExFill(sizeof(shellcode), PAGE_EXECUTE_READWRITE);

	EntryPoint += dll.RemoteBase;
	EntryPoint -= (reinterpret_cast<DWORD>(ShellAddress) + 26);

	const BYTE* pShell = shellcode;
	DWORD ShellSize = sizeof(shellcode);

	// Getting the address of TlsAlloc in the target process if there is a .tls section

	const DWORD TlsDirectoryVA = GetDataDirectory(dll.NtHeader, DIRECTORY_ENTRY_TLS).VirtualAddress;

	if (TlsDirectoryVA)
	{
		static HMODULE kernelbase = nullptr;

		if (!kernelbase)
		{
			kernelbase = GetModuleHandle(L"KernelBase.dll");
			DWORD pTlsAlloc = reinterpret_cast<DWORD>(GetProcAddress(kernelbase, "TlsAlloc"));

			DLL_DATA* KernelBaseEntry = nullptr;
			FindModuleEntry("KernelBase.dll", &KernelBaseEntry);

			pTlsAlloc = ((pTlsAlloc - reinterpret_cast<DWORD>(kernelbase)) + KernelBaseEntry->RemoteBase) - (reinterpret_cast<DWORD>(ShellAddress) + 5);
			memcpy(&shellcode[1], &pTlsAlloc, sizeof(DWORD));
		}

		TLS_DIRECTORY* TlsDirectory = GetMappedVA<TLS_DIRECTORY*>(&dll, TlsDirectoryVA);
		memcpy(&shellcode[6], &TlsDirectory->AddressOfIndex, sizeof(DWORD));
	}
	else
	{
		pShell += 12;
		ShellSize -= 12;
		EntryPoint += 12;
	}

	// Setting hinstDLL/DllMain

	memcpy(&shellcode[17], &dll.RemoteBase, sizeof(DWORD)); // hinstDLL
	memcpy(&shellcode[22], &EntryPoint,     sizeof(DWORD)); // DllMain

	// Writing shellcode into memory

	if (!WPM(ShellAddress, pShell, ShellSize))
	{
		ERR_OUT("Failed to write shellcode to memory!\n");
		return false;
	}

	DNDBG_OUT("DLL/EP: " << dll.DllName << "/0x" << HEX(ShellAddress));

	HANDLE thread = CreateRemoteThreadFill(ShellAddress, nullptr);
	if (WaitForSingleObject(thread, 1500) != WAIT_OBJECT_0)
	{
		NERR_OUT("Failed to execute DllMain for: " << dll.DllPath);
		CloseHandle(thread);
		return false;
	}

	CloseHandle(thread);
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

	void* DllBuffer = VirtualAllocExFill(PathSize, PAGE_READWRITE);
	if (!DllBuffer)
	{
		CERR_OUT("VirtualAllocEx failed!");
		return false;
	}

	if (!WPM(DllBuffer, DllPath, PathSize))
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