#include "pch.hpp"
#include "mMap.hpp"
#include "ImagePrep.hpp"
#include "helpers.hpp"
#include "ModuleResolve.hpp"

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

int FindModuleEntry(const char* name, DLL_DATA** buffer, int flags)
{
	for (UINT i = 0; i < modules.size(); ++i)
	{
		DLL_DATA* dll = &modules[i];

		if (!_stricmp(dll->DllName.c_str(), name))
		{
			if (dll->flags & RedirectModule)
			{
				i = dll->HostIndex;

				if (flags & ReturnApiHost)
				{
					dll = &modules[i];
				}
			}
			
			if (flags & LocalLoadImage && !dll->FirstSection)
			{
				dll->DllPath.reserve(MAX_PATH);

				if (!GetModulePath(dll->DllName.c_str(), dll->DllPath.data()) || !LoadDll(dll->DllPath.c_str(), dll))
				{
					return -1;
				}
			}

			*buffer = dll;
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

void GetExportInfo(DLL_DATA* dll, EXPORT_INFO* ExportInfo)
{
	ExportInfo->ExportDir    = &GetDataDirectory(dll->NtHeader, DIRECTORY_ENTRY_EXPORT);
	ExportInfo->ExportTable  = GetMappedVA<EXPORT_DIRECTORY*>(dll, ExportInfo->ExportDir->VirtualAddress);
	ExportInfo->NameTable    = GetMappedRVA<DWORD*>(dll, ExportInfo->ExportTable->AddressOfNames);
	ExportInfo->OrdinalTable = GetMappedRVA<WORD*> (dll, ExportInfo->ExportTable->AddressOfNameOrdinals);
	ExportInfo->EAT          = GetMappedRVA<DWORD*>(dll, ExportInfo->ExportTable->AddressOfFunctions);
}