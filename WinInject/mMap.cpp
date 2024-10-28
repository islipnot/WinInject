#include "pch.hpp"
#include "mMap.hpp"
#include "process.hpp"
#include "ModuleResolve.hpp"
#include "ImagePrep.hpp"
#include "helpers.hpp"

std::vector<DLL_DATA> modules(1);

bool LoadDll(const char* path, DLL_DATA* DllData)
{
	NDBG_OUT("Loading image: " << path);

	// Loading the image into memory

	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (file.fail())
	{
		ERR_OUT("Failed to open file\n");
		return false;
	}

	const size_t ImageSz = static_cast<size_t>(file.tellg());
	char* base = new char[ImageSz];

	file.seekg(0, std::ios::beg);
	file.read(base, ImageSz);
	file.close();

	// Initializing the DLL_DATA structure

	std::string& DllPath = DllData->DllPath;

	DllPath = path;
	if (DllData->DllName.empty()) DllData->DllName = PathToFileName(DllPath);

	if (!(DllData->flags & RedirectModule))
	{
		NT_HEADERS* NtHeader  = ImageNtHeader(base);
		DllData->NtHeader     = NtHeader;
		DllData->FirstSection = IMAGE_FIRST_SECTION(NtHeader);
		DllData->SectionCount = NtHeader->FileHeader.NumberOfSections;
	}

	DllData->pLocalBase = base;

	DBG_OUT("Success!\n\n");
	return true;
}

bool ManualMapDll(const char* path)
{
	if (!LoadDll(path, &modules.back()) || !GetLoadedModules())
		return false;

	DBG_OUT("> Resolving dependencies\n\n");

	for (UINT i = 0; i < modules.size(); ++i)
	{
		if ((modules[i].flags & (RemoteLoaded | RedirectModule)))
			continue;

		if (!ResolveDependencies(i))
			return false;
	}

	DBG_OUT("> Allocating memory\n\n");

	for (DLL_DATA& dll : modules)
	{
		if (dll.flags & (RemoteLoaded | RedirectModule))
			continue;

		void* RemoteBase = VirtualAllocExFill(hProcess, dll.NtHeader->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);

		if (!RemoteBase)
		{
			NDBG_OUT("Failed to allocate memory for: " << dll.DllPath);
			return false;
		}
		else
		{
			NDBG_OUT("Memory allocated for: " << dll.DllName);
			DNDBG_OUT("Base/size: 0x" << HEX(RemoteBase) << "/0x" << dll.NtHeader->OptionalHeader.SizeOfImage);
		}

		dll.pRemoteBase = RemoteBase;
	}

	DBG_OUT("> Relocating and resolving imports\n\n");

	for (DLL_DATA& dll : modules)
	{
		if (dll.flags & (RemoteLoaded | RedirectModule))
			continue;

		if (!RelocateImage(&dll) || !SnapImports(&dll))
			return false;
	}

	DBG_OUT("> Writing modules into target memory\n\n");

	for (DLL_DATA& dll : modules)
	{
		if (dll.flags & (RemoteLoaded | RedirectModule))
			continue;

		if (!RemoteMapModule(&dll))
			return false;
	}

	return true;
}