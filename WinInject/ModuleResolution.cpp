#pragma warning(disable : 28193)

#include "pch.hpp"
#include "mMap.hpp"
#include "helpers.hpp"
#include "ModuleResolve.hpp"

bool ResolveNtFileName(char* path)
{
	// Based on ntdll.dll!LdrpMapDllNtFileName

	WCHAR NtPath[MAX_PATH] = L"\\??\\";
	mbstowcs(NtPath + 4, path, MAX_PATH);

	UNICODE_STRING uPath;
	uPath.Buffer = NtPath;
	uPath.Length = static_cast<USHORT>(wcslen(NtPath)) << 1;
	uPath.MaximumLength = uPath.Length + 2;

	OBJECT_ATTRIBUTES attribs;
	attribs.Length = sizeof(OBJECT_ATTRIBUTES);
	attribs.RootDirectory = 0;
	attribs.Attributes = OBJ_CASE_INSENSITIVE;
	attribs.SecurityDescriptor = 0;
	attribs.SecurityQualityOfService = 0;
	attribs.ObjectName = &uPath;

	HANDLE hFile;
	IO_STATUS_BLOCK StatusBlock;
	if (!NT_SUCCESS(NtOpenFile(&hFile, SYNCHRONIZE | FILE_TRAVERSE | FILE_READ_DATA, &attribs, &StatusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT)))
	{
		ERR_OUT("Failed to open NT file!\n");
		return false;
	}

	WCHAR FinalPath[MAX_PATH];
	GetFinalPathNameByHandle(hFile, FinalPath, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
	wcstombs(path, FinalPath + 4, MAX_PATH);
	NtClose(hFile);

	return true;
}

bool GetModulePath(const char* DllName, char* ResolvedPath)
{
	// NDBG_OUT("Resolving module path: " << DllName);

	// Getting target process directory

	static char ProcessDir[MAX_PATH]{ '\0' };

	if (!ProcessDir[0]) // modules[1] will always be the target process
	{
		const std::string& DllPath = modules[1].DllPath;
		const std::string dir = DllPath.substr(0, DllPath.size() - modules[1].DllName.size());
		memcpy(ProcessDir, dir.c_str(), dir.size());
	}

	// Searching target process directory

	if (SearchPathA(ProcessDir, DllName, nullptr, MAX_PATH, ResolvedPath, nullptr))
	{
		// DNDBG_OUT("Resolved path: " << ResolvedPath);
		return true;
	}

	// Searching default search paths

	if (!SearchPathA(nullptr, DllName, nullptr, MAX_PATH, ResolvedPath, nullptr))
	{
		DBG_OUT("Failed to resolve path!\n");
		return false;
	}

	if (!ResolveNtFileName(ResolvedPath))
		return false;

	// DNDBG_OUT("Resolved path: " << ResolvedPath);
	return true;
}

NAMESPACE_ENTRY* ApiSetpSearchForApiSet(NAMESPACE_HEADER* ApiSetMap, PWSTR ApiName, UINT16 ApiSubNameSz)
{
	DWORD ApiHash = 0;

	if (ApiSubNameSz) // Hashing API Set name
	{
		PWSTR pApiName = ApiName;

		for (int i = ApiSubNameSz; i; --i)
		{
			WCHAR ch = *pApiName;

			if (static_cast<UINT16>(ch - 65) <= 25u) // Casting to UINT16 prevents non-letters ('-'/digits) from being converted
				ch += 32; // Converting char to lowercase if its uppercase

			++pApiName;
			ApiHash = ch + (ApiSetMap->Multiplier * ApiHash);
		}
	}

	int UpperBound = 0;
	int LowerBound = ApiSetMap->ApiSetCount - 1;
	if (LowerBound < 0) return nullptr;

	DWORD HashOffset = ApiSetMap->HashOffset;
	DWORD HashEntryOffset;

	while (true) // Performing binary search for the corresponding HASH_ENTRY structure
	{
		const int EntryIndex = (LowerBound + UpperBound) >> 1;
		HashEntryOffset = HashOffset + (sizeof(HASH_ENTRY) * EntryIndex);

		if (ApiHash < *(DWORD*)(reinterpret_cast<char*>(ApiSetMap) + HashEntryOffset))
		{
			LowerBound = EntryIndex - 1;
		}
		else
		{
			if (ApiHash <= *(DWORD*)(reinterpret_cast<char*>(ApiSetMap) + HashEntryOffset))
				break;

			UpperBound = EntryIndex + 1;
		}

		if (UpperBound > LowerBound)
			return nullptr;
	}

	const DWORD NsEntryOffset = ApiSetMap->NsEntryOffset + (sizeof(NAMESPACE_ENTRY) * *reinterpret_cast<DWORD*>(reinterpret_cast<char*>(ApiSetMap) + HashEntryOffset + 4));
	NAMESPACE_ENTRY* NsEntry = reinterpret_cast<NAMESPACE_ENTRY*>(reinterpret_cast<char*>(ApiSetMap) + NsEntryOffset);

	if (!NsEntry) return 0;

	if (!_wcsnicmp(ApiName, reinterpret_cast<PCWSTR>(reinterpret_cast<char*>(ApiSetMap) + NsEntry->ApiNameOffset), ApiSubNameSz))
		return NsEntry;

	return nullptr;
}

bool ApiSetResolveToHost(const UNICODE_STRING* ApiName, std::string* HostName)
{
	static NAMESPACE_HEADER* ApiSetMap = GetApiSetMap();
	const UINT NameLen = static_cast<UINT>(ApiName->Length);

	if (NameLen >= 8) // wcslen(L"api-") * sizeof(WCHAR) == wcslen(L"ext-") * sizeof(WCHAR) == 8
	{
		const PWSTR pApiName = ApiName->Buffer;
		const DWORD Mask1 = *reinterpret_cast<DWORD*>(pApiName) & API_MASK_LOW;
		const DWORD Mask2 = *(reinterpret_cast<DWORD*>(pApiName) + 1) & API_MASK_HIGH;

		if ((Mask1 == API_LOW && Mask2 == API_HIGH) || (Mask1 == EXT_LOW && Mask2 == EXT_HIGH))
		{
			UINT16 wSubNameSz = static_cast<UINT16>(NameLen);
			PWCHAR ch = reinterpret_cast<PWCHAR>(reinterpret_cast<char*>(pApiName) + wSubNameSz);

			do
			{
				if (wSubNameSz <= 1)
					break;

				--ch;
				wSubNameSz -= 2;
			} while (*ch != '-');

			const UINT16 SubNameSz = wSubNameSz >> 1;

			if (SubNameSz)
			{
				const NAMESPACE_ENTRY* NsEntry = ApiSetpSearchForApiSet(ApiSetMap, pApiName, SubNameSz);

				if (NsEntry)
				{
					const HOST_ENTRY* HostEntry = reinterpret_cast<HOST_ENTRY*>(reinterpret_cast<char*>(ApiSetMap) + NsEntry->HostEntryOffset);

					if (NsEntry->HostCount)
					{
						wcstombs(HostName->data(), reinterpret_cast<PWSTR>((reinterpret_cast<char*>(ApiSetMap) + HostEntry->ValueOffset)), HostEntry->ValueLength >> 1);
						return true;
					}
				}
			}
		}
	}

	return false;
}

bool InsertModuleEntry(const char* DllName)
{
	// Checking to see if an entry for this module already exists

	DLL_DATA* ExistingEntry = nullptr;
	const UINT ExistingEntryIndex = FindModuleEntry(DllName, &ExistingEntry);

	if (ExistingEntry != nullptr && ExistingEntry->flags & (RedirectModule | LocalLoaded))
	{
		return true;
	}

	// Checking if the module is an API set

	std::string ApiHostName(MAX_PATH, '\0');

	UNICODE_STRING uDllName;
	CreateUnicodeString(DllName, &uDllName);

	const bool IsApiSet = ApiSetResolveToHost(&uDllName, &ApiHostName);
	delete[] uDllName.Buffer;

	// Creating and initializing a DLL_DATA struct for the module entry

	DLL_DATA ModuleEntry;
	if (ExistingEntry) ModuleEntry = *ExistingEntry;
	else ModuleEntry.DllName = DllName;

	DLL_DATA* HostEntry = nullptr;
	ModuleEntry.DllPath.resize(MAX_PATH);

	if (IsApiSet)
	{
		DNDBG_OUT("API set detected: " << DllName << " -> " << ApiHostName);

		if (!GetModulePath(ApiHostName.c_str(), ModuleEntry.DllPath.data()))
		{
			return false;
		}

		ModuleEntry.flags |= RedirectModule;
		const UINT HostEntryIndex = FindModuleEntry(ApiHostName.c_str(), &HostEntry);

		if (HostEntryIndex != -1)
		{
			ModuleEntry.HostIndex = HostEntryIndex;
		}
	}
	else if (!GetModulePath(DllName, ModuleEntry.DllPath.data()))
	{
		return false;
	}

	// Loading the image into local memory, if needed

	if (IsApiSet && !HostEntry)
	{
		ModuleEntry.HostIndex = modules.size();

		if (!InsertModuleEntry(ApiHostName.c_str()))
		{
			return false;
		}
	}
	else if (!IsApiSet)
	{
		if (!ModuleEntry.LocalBase && !LoadDll(ModuleEntry.DllPath.c_str(), &ModuleEntry))
		{
			return false;
		}

		ModuleEntry.flags |= LocalLoaded;
	}

	if (ExistingEntry) *ExistingEntry = ModuleEntry;
	else modules.emplace_back(ModuleEntry);

	return true;
}

bool ResolveDependencies(UINT index)
{
	DLL_DATA* dll = &modules[index];

	// Getting import directory table

	const DWORD ImportTableVA = GetDataDirectory(dll->NtHeader, DIRECTORY_ENTRY_IMPORT).VirtualAddress;
	const IMPORT_DESCRIPTOR* ImportDir = GetMappedVA<IMPORT_DESCRIPTOR*>(dll, ImportTableVA);
	char* DllBase = dll->pLocalBase;

	// Loading imported modules

	while (ImportDir->FirstThunk)
	{
		const char* DllName = GetMappedRVA<const char*>(dll, ImportDir->Name);

		// Handling the dependency

		if (!InsertModuleEntry(DllName))
		{
			return false;
		}

		++ImportDir;
		dll = &modules[index];
	}

	return true;
}