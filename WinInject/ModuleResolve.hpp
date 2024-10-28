#pragma once

// Enums

enum STRING_MASKS // ApiSetResolveToHost
{
	API_MASK_HIGH = 0x0FFFFFFDF,
	API_MASK_LOW = 0x0FFDFFFDF,
	API_HIGH = 0x0002D0049, // "AP"
	API_LOW = 0x000500041, // "I" (following char isn't checked)
	EXT_HIGH = 0x0002D0054, // "T" (following char isn't checked)
	EXT_LOW = 0x000580045, // "EX"
};

// Structs

typedef struct API_SET_VALUE_ENTRY // https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
{
	DWORD Flags;
	DWORD NameOffset;
	DWORD NameLength;
	DWORD ValueOffset;
	DWORD ValueLength;
} HOST_ENTRY;

struct NAMESPACE_HEADER // https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
{
	DWORD SchemaExt;
	DWORD MapSizeByte;
	DWORD Flags;
	DWORD ApiSetCount;
	DWORD NsEntryOffset;
	DWORD HashOffset;
	DWORD Multiplier;
};

typedef struct API_SET_NAMESPACE_ENTRY // https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
{
	DWORD Flags;
	DWORD ApiNameOffset;
	DWORD ApiNameSz;
	DWORD ApiSubNameSz;
	DWORD HostEntryOffset;
	DWORD HostCount;
} NAMESPACE_ENTRY;

struct HASH_ENTRY // https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
{
	DWORD ApiHash;
	DWORD ApiIndex;
};

// Forward declarations

bool GetModulePath(const char* DllName, char* ResolvedPath);

bool ResolveDependencies(UINT index);