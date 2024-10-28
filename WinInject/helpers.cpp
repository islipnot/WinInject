#include "pch.hpp"
#include "mMap.hpp"
#include "helpers.hpp"

UINT PathToFileOffset(const std::string& path)
{
	size_t FileNamePos = path.find_last_of('\\');

	if (FileNamePos == std::string::npos) FileNamePos = path.find_last_of('/');
	if (FileNamePos == std::string::npos) FileNamePos = static_cast<size_t>(-1);

	return FileNamePos + 1;
}

DWORD GetMappedAddress(const DLL_DATA* DllData, DWORD VirtAddress, DWORD base)
{
	// Based on ntdll.dll!RtlAddressInSectionTable / ntdll.dll!RtlImageRvaToVa

	const SECTION_HEADER* section = DllData->FirstSection;
	const UINT NumberOfSections = DllData->SectionCount;

	for (UINT i = 0; i < NumberOfSections; ++i, ++section)
	{
		const DWORD SectionVA = section->VirtualAddress;

		if (VirtAddress >= SectionVA && VirtAddress < SectionVA + section->SizeOfRawData)
		{
			return base + (section->PointerToRawData - SectionVA) + VirtAddress;
		}
	}

	ERR_OUT("Failed to resolve virtual address!\n");

	system("pause");
	__fastfail(FAST_FAIL_INVALID_ARG); // done so that error handling isnt required on every call to GetMappedAddress
}

int FindModuleEntry(const char* name, DLL_DATA** buffer, bool LocalLoadedOnly)
{
	for (int i = 0; i < modules.size(); ++i)
	{
		if (!_stricmp(modules[i].DllName.c_str(), name))
		{
			if (modules[i].flags & RedirectModule)
			{
				i = modules[i].HostIndex;
			}
			else if (LocalLoadedOnly && !modules[i].NtHeader) return -2;

			*buffer = &modules[i];
			return i;
		}
	}

	return -1;
}

void CreateUnicodeString(const char* str, UNICODE_STRING* uStr)
{
	const UINT StringSz = strlen(str);
	PWCHAR Buffer = new WCHAR[StringSz];

	uStr->Buffer = Buffer;
	uStr->Length = static_cast<USHORT>(StringSz << 1);
	uStr->MaximumLength = uStr->Length + sizeof(WCHAR);

	mbstowcs(Buffer, str, StringSz);
}