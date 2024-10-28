#include "pch.hpp"
#include "mMap.hpp"
#include "helpers.hpp"
#include "ImagePrep.hpp"

bool RelocateImage(const DLL_DATA* image)
{
	// Based on ntdll.dll!LdrpGenericProcessRelocation

	// Getting base relocation table

	const DATA_DIRECTORY* RelocTableData = &GetDataDirectory(image->NtHeader, DIRECTORY_ENTRY_BASERELOC);
	BASE_RELOCATION* RelocTable = GetLocalMappedVA<BASE_RELOCATION*>(image, RelocTableData->VirtualAddress);
	const BYTE* RelocTableEnd = reinterpret_cast<BYTE*>(RelocTable) + RelocTableData->Size;

	const DWORD BaseDifference = image->RemoteBase - image->NtHeader->OptionalHeader.ImageBase;
	if (BaseDifference == 0) return true;

	// While loop goes through each relocation block

	while (reinterpret_cast<BYTE*>(RelocTable) < RelocTableEnd)
	{
		RELOC_ENTRY* RelocEntry = reinterpret_cast<RELOC_ENTRY*>(RelocTable + 1);
		RELOC_ENTRY* BlockEnd = reinterpret_cast<RELOC_ENTRY*>((RelocTable->SizeOfBlock - sizeof(BASE_RELOCATION)) >> 1);

		// Applying relocation to each entry in the block

		while (RelocEntry < BlockEnd) // Only ABSOLUTE/HIGHLOW are dealt with, I have not seen a single other type in a PE32 file
		{
			if (RelocEntry->Type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			DWORD* RelocAddress = GetLocalMappedVA<DWORD*>(image, RelocTable->VirtualAddress + RelocEntry->Offset);
			*RelocAddress += BaseDifference;

			++RelocEntry;
		}

		RelocTable = reinterpret_cast<BASE_RELOCATION*>(reinterpret_cast<BYTE*>(RelocTable) + RelocTable->SizeOfBlock);
	}

	NDBG_OUT("Image relocated: " << image->DllName);
	return true;
}

DWORD GetExportAddress(DLL_DATA* dll, const char* TargetName, EXPORT_INFO& info)
{
	for (UINT i = 0; i < info.ExportTable->NumberOfNames; ++i)
	{
		// Check the name table for a matching export

		const char* ExportName = GetLocalMappedRVA<const char*>(dll, info.NameTable[i]);
		if (_stricmp(TargetName, ExportName) != 0) continue;

		// Handle matching export if found

		const DWORD FunctionRVA = info.EAT[static_cast<DWORD>(info.OrdinalTable[i])];

		if (FunctionRVA < info.ExportDir->VirtualAddress && FunctionRVA >= info.ExportDir->VirtualAddress + info.ExportDir->Size)
		{
			return GetLocalMappedRVA(dll, FunctionRVA); // RVA being outside of the export directory means it isn't a forwarder
		}

		// Handling forwarder
	}

	//NERR_OUT("Failed to get export address: " << TargetName);
	return 1;
}

bool SnapImports(const DLL_DATA* image)
{
	// ntdll.dll!LdrpSnapModule

	const DWORD ImportTableVA = GetDataDirectory(image->NtHeader, DIRECTORY_ENTRY_IMPORT).VirtualAddress;
	const IMPORT_DESCRIPTOR* ImportDir = GetLocalMappedVA<IMPORT_DESCRIPTOR*>(image, ImportTableVA);

	while (ImportDir->FirstThunk)
	{
		const char* DllName = GetLocalMappedRVA<const char*>(image, ImportDir->Name);

		DLL_DATA* ImportedModule = nullptr;
		if (FindModuleEntry(DllName, &ImportedModule, true) == -1)
		{
			NERR_OUT("Failed to locate imported module post dependency resolution: " << DllName);
			return false;
		}

		if (ImportedModule->flags & RedirectModule)
		{
			ImportedModule = &modules[ImportedModule->HostIndex];
		}

		// Import address/lookup tables

		THUNK_DATA* IAT = GetLocalMappedRVA<THUNK_DATA*>(image, ImportDir->FirstThunk);
		THUNK_DATA* ILT = GetLocalMappedRVA<THUNK_DATA*>(image, ImportDir->Characteristics);

		EXPORT_INFO ExportInfo;
		ExportInfo.ExportDir    = &GetDataDirectory(ImportedModule->NtHeader, DIRECTORY_ENTRY_EXPORT);
		ExportInfo.ExportTable  = GetLocalMappedVA<EXPORT_DIRECTORY*>(ImportedModule, ExportInfo.ExportDir->VirtualAddress);
		ExportInfo.NameTable    = GetLocalMappedRVA<DWORD*>(ImportedModule, ExportInfo.ExportTable->AddressOfNames);
		ExportInfo.OrdinalTable = GetLocalMappedRVA<WORD*>(ImportedModule,  ExportInfo.ExportTable->AddressOfNameOrdinals);
		ExportInfo.EAT          = GetLocalMappedRVA<DWORD*>(ImportedModule, ExportInfo.ExportTable->AddressOfFunctions);

		while (ILT->u1.Function) // Need to add ordinal import support
		{
			const char* ImportName = GetLocalMappedVA<IMPORT_BY_NAME*>(image, ILT->u1.ForwarderString)->Name;

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