#pragma once

#ifndef IMG_PREP_INCLUDED
	#include "ImagePrep.hpp"
#endif

// Enums

enum EntryLocationFlags
{
	LocalLoadImage = 1,
	ReturnApiHost  = 2
};

// Forward declarations

UINT PathToFileOffset(const std::string& path);

DWORD GetMappedAddress(const DLL_DATA* DllData, DWORD VirtAddress, DWORD base);

int FindModuleEntry(const char* name, DLL_DATA** buffer, int flags = NULL);

void CreateUnicodeString(const char* str, UNICODE_STRING* uStr);

void GetExportInfo(DLL_DATA* dll, EXPORT_INFO* ExportInfo);

// Templates

template <typename ret = DWORD> auto GetLocalMappedAddress(const DLL_DATA* DllData, DWORD VirtAddress) -> ret
{
	return (ret)(GetMappedAddress(DllData, VirtAddress, DllData->LocalBase));
}

template <typename ret = DWORD> auto GetRemoteMappedAddress(const DLL_DATA* DllData, DWORD VirtAddress) -> ret
{
	return (ret)(GetMappedAddress(DllData, VirtAddress, DllData->RemoteBase));
}

// Macros

/* RVA/VA resolution */

#define GetMappedRVA GetLocalMappedAddress

#define GetMappedVA  GetLocalMappedAddress

/* General macros */

#define PathToFileName(path) path.substr(PathToFileOffset(path))

#define GetDataDirectory(NtHeader, dir) NtHeader->OptionalHeader.DataDirectory[dir]

#define GetApiSetMap() static_cast<NAMESPACE_HEADER*>(NtCurrentTeb()->ProcessEnvironmentBlock->Reserved9[0])

/* Data directories */

#define DIRECTORY_ENTRY_EXPORT    IMAGE_DIRECTORY_ENTRY_EXPORT

#define DIRECTORY_ENTRY_IMPORT    IMAGE_DIRECTORY_ENTRY_IMPORT

#define DIRECTORY_ENTRY_BASERELOC IMAGE_DIRECTORY_ENTRY_BASERELOC

#define DIRECTORY_ENTRY_TLS       IMAGE_DIRECTORY_ENTRY_TLS

#define DIRECTORY_ENTRY_IAT       IMAGE_DIRECTORY_ENTRY_IAT