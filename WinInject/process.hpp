#pragma once

// Macros

#define VirtualAllocExFill(dwSize, flProtect) VirtualAllocEx(hProcess, nullptr, dwSize, MEM_COMMIT | MEM_RESERVE, flProtect)

#define CreateRemoteThreadFill(lpStartAddress, lpParameter) CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpStartAddress), lpParameter, 0, nullptr)

#define WPM(lpBaseAddress, lpBuffer, nSize) WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, nullptr)

// Forward declarations

extern HANDLE hProcess;

bool GetLoadedModules();

bool RemoteMapModule(DLL_DATA* dll);

bool RunDllMain(DLL_DATA& dll);

bool GetProcessHandle(PCWSTR ProcessName);

bool LoadLibInject(PCWSTR DllPath);