#pragma once

// Debugging macros

#define ERR_OUT(error) std::cerr << error

#define NERR_OUT(error) std::cerr << error << '\n'

#define CERR_OUT(error) std::cerr << error << " Error code: " << GetLastError() << '\n'

#ifdef _DEBUG
	#define HEX(output) std::hex << std::uppercase << output << std::dec
	#define DBG_OUT(output) std::cout << output
	#define NDBG_OUT(output) std::cout << output << '\n'
	#define DNDBG_OUT(output) std::cout << output << "\n\n"
#else
	#define HEX(output)
	#define DBG_OUT(output)
	#define NDBG_OUT(output)
	#define DNDBG_OUT(output)
#endif

// Libraries

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Imagehlp.lib")

// General macros

#define _CRT_SECURE_NO_WARNINGS

#define WIN32_LEAN_AND_MEAN

#define MANUAL_MAP   0

#define LOAD_LIBRARY 1

// WinAPI headers

#include <Windows.h>
#include <Shlwapi.h>
#include <Winternl.h>
#include <TlHelp32.h>
#include <ImageHlp.h>
#include <Psapi.h>

// Standard headers

#include <iostream>
#include <fstream>
#include <string>
#include <vector>