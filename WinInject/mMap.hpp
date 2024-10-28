#pragma once

// Typedefs

typedef IMAGE_NT_HEADERS32 NT_HEADERS;

typedef IMAGE_SECTION_HEADER SECTION_HEADER;

typedef IMAGE_DATA_DIRECTORY DATA_DIRECTORY;

typedef IMAGE_IMPORT_DESCRIPTOR IMPORT_DESCRIPTOR;

typedef IMAGE_EXPORT_DIRECTORY EXPORT_DIRECTORY;

typedef IMAGE_IMPORT_BY_NAME IMPORT_BY_NAME;

typedef IMAGE_THUNK_DATA32 THUNK_DATA;

typedef IMAGE_BASE_RELOCATION BASE_RELOCATION;

// Enums

enum DLL_DATA_FLAGS
{
	RedirectModule = 1,
	RemoteLoaded = 2,
	LocalLoaded = 4
};

// Structs

struct DLL_DATA
{
	SECTION_HEADER* FirstSection = nullptr;
	NT_HEADERS* NtHeader = nullptr;
	UINT SectionCount = 0;

	union
	{
		char* pLocalBase = nullptr;
		DWORD LocalBase;
		UINT HostIndex;
	};

	union
	{
		void* pRemoteBase = nullptr;
		DWORD RemoteBase;
	};

	std::string DllPath; // If API set, DllPath == host path
	std::string DllName;
	UINT flags = 0;
};

// Forward declarations

extern std::vector<DLL_DATA> modules;

bool LoadDll(const char* path, DLL_DATA* DllData);

bool ManualMapDll(const char* DllPath);