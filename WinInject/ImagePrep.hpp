#pragma once

// Structs

struct RELOC_ENTRY
{
	WORD Offset : 12;
	WORD Type : 4;
};

struct EXPORT_INFO
{
	DATA_DIRECTORY* ExportDir;
	EXPORT_DIRECTORY* ExportTable;
	DWORD* EAT;
	DWORD* NameTable;
	WORD* OrdinalTable;
};

// Forward declarations

bool RelocateImage(const DLL_DATA* image);

bool SnapImports(const DLL_DATA* image);