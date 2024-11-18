#include "pch.hpp"
#include "mMap.hpp"
#include "ImagePrep.hpp"
#include "helpers.hpp"

bool RelocateImage(const DLL_DATA* image)
{
	// Based on ntdll.dll!LdrpGenericProcessRelocation

	// Getting base relocation table

	const DATA_DIRECTORY* RelocTableData = &GetDataDirectory(image->NtHeader, DIRECTORY_ENTRY_BASERELOC);
	BASE_RELOCATION* RelocTable = GetMappedVA<BASE_RELOCATION*>(image, RelocTableData->VirtualAddress);
	const BYTE* RelocTableEnd = reinterpret_cast<BYTE*>(RelocTable) + RelocTableData->Size;

	const DWORD BaseDifference = image->RemoteBase - image->NtHeader->OptionalHeader.ImageBase;
	if (BaseDifference == 0) return true;

	// While loop goes through each relocation block

	int applied_relocs = 0;

	while (reinterpret_cast<BYTE*>(RelocTable) < RelocTableEnd)
	{
		RELOC_ENTRY* RelocEntry = reinterpret_cast<RELOC_ENTRY*>(RelocTable + 1);
		RELOC_ENTRY* BlockEnd = reinterpret_cast<RELOC_ENTRY*>(((RelocTable->SizeOfBlock - sizeof(BASE_RELOCATION)) >> 1) + RelocEntry);

		// Applying relocation to each entry in the block

		while (RelocEntry < BlockEnd) // Only ABSOLUTE/HIGHLOW are dealt with, I have not seen a single other type in a PE32 file
		{
			if (RelocEntry->Type != IMAGE_REL_BASED_ABSOLUTE)
			{
				DWORD* RelocAddress = GetMappedVA<DWORD*>(image, RelocTable->VirtualAddress + RelocEntry->Offset);
				*RelocAddress += BaseDifference;
				++applied_relocs;
			}

			++RelocEntry;
		}

		RelocTable = reinterpret_cast<BASE_RELOCATION*>(reinterpret_cast<BYTE*>(RelocTable) + RelocTable->SizeOfBlock);
	}

	DNDBG_OUT("Image relocated: " << image->DllName << " (" << applied_relocs << ')');
	return true;
}

DWORD GetExportAddress(DLL_DATA* dll, const char* TargetName, EXPORT_INFO& info)
{
	for (UINT i = 0; i < info.ExportTable->NumberOfNames; ++i)
	{
		// Check the name table for a matching export

		const char* ExportName = GetMappedRVA<const char*>(dll, info.NameTable[i]);
		if (_stricmp(TargetName, ExportName) != 0) continue;

		// Handle matching export if found

		const DWORD ExportRVA = info.EAT[info.OrdinalTable[i]];

		if (ExportRVA < info.ExportDir->VirtualAddress || ExportRVA >= info.ExportDir->VirtualAddress + info.ExportDir->Size)
		{
			return dll->RemoteBase + ExportRVA; // RVA being outside of the export directory means it isn't a forwarder
		}

		// Handling forwarders

		ExportName = GetMappedRVA<const char*>(dll, ExportRVA);

		std::string forwarder = ExportName;
		forwarder.erase(forwarder.find_last_of('.'));

		if (forwarder.find('.') == std::string::npos)
		{
			forwarder += ".dll";
		}

		DLL_DATA* ForwarderEntry = nullptr;
		if (FindModuleEntry(forwarder.c_str(), &ForwarderEntry, ReturnApiHost | LocalLoadImage) == -1)
		{
			return 0;
		}

		forwarder = ExportName;
		forwarder.erase(0, forwarder.find_last_of('.') + 1);

		EXPORT_INFO ForwarderExportInfo;
		GetExportInfo(ForwarderEntry, &ForwarderExportInfo);

		return GetExportAddress(ForwarderEntry, forwarder.c_str(), ForwarderExportInfo);
	}

	NERR_OUT("Failed to get export address: " << TargetName);
	return 0;
}

bool SnapImports(const DLL_DATA* image)
{
	// ntdll.dll!LdrpSnapModule

	const DWORD ImportTableVA = GetDataDirectory(image->NtHeader, DIRECTORY_ENTRY_IMPORT).VirtualAddress;
	const IMPORT_DESCRIPTOR* ImportDir = GetMappedVA<IMPORT_DESCRIPTOR*>(image, ImportTableVA);

	while (ImportDir->FirstThunk)
	{
		const char* DllName = GetMappedRVA<const char*>(image, ImportDir->Name);

		DLL_DATA* ImportedModule = nullptr;
		if (FindModuleEntry(DllName, &ImportedModule, ReturnApiHost | LocalLoadImage) == -1)
		{
			NERR_OUT("Failed to locate imported module post dependency resolution: " << DllName);
			return false;
		}

		if (ImportedModule->flags & RedirectModule)
		{
			ImportedModule = &modules[ImportedModule->HostIndex];
		}

		// Import address/lookup tables

		THUNK_DATA* IAT = GetMappedRVA<THUNK_DATA*>(image, ImportDir->FirstThunk);
		THUNK_DATA* ILT = GetMappedRVA<THUNK_DATA*>(image, ImportDir->Characteristics);

		EXPORT_INFO ExportInfo;
		GetExportInfo(ImportedModule, &ExportInfo);

		while (ILT->u1.Function) // Need to add ordinal import support
		{
			const char* ImportName = GetMappedVA<IMPORT_BY_NAME*>(image, ILT->u1.ForwarderString)->Name;

			const DWORD ExportAddr = GetExportAddress(ImportedModule, ImportName, ExportInfo);
			if (!ExportAddr) return false;

			IAT->u1.AddressOfData = ExportAddr;
			++ILT, ++IAT;
		}
		 
		++ImportDir;
	}

	DNDBG_OUT("Imports snapped: " << image->DllName);
	return true;
}