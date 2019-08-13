#include "pch.h"
#include "MurmurHash2A.h"
#include "PointerHashFunc.h"
#include "export_work.h"

HANDLE hash_CreateFileA(
	__in    LPCSTR      file_name,
	__in    DWORD     access,
	__in    DWORD     share_mode,
	__in    LPSECURITY_ATTRIBUTES security,
	__in    DWORD     creation_disposition,
	__in    DWORD     flags,
	__in HANDLE    template_file) {

	unsigned int _hash = MurmurHash2A("CreateFileA", 12, 12);

	temp_CreateFile = (HANDLE(WINAPI *)(LPCSTR,
		DWORD,
		DWORD,
		LPSECURITY_ATTRIBUTES,
		DWORD,
		DWORD,
		HANDLE))get_api(_hash, "kernel32.dll", 12, 12);

	return temp_CreateFile(file_name, access, share_mode, security, creation_disposition, flags, template_file);
}

BOOL hash_VirtualProtect(LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect) {

	unsigned int _hash = MurmurHash2A("VirtualProtect", 15, 15);

	temp_VirtualProtect = (BOOL(WINAPI*)(LPVOID,
		SIZE_T,
		DWORD,
		PDWORD))get_api(_hash, "kernel32.dll", 15, 15);

	return temp_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

LPVOID hash_VirtualAlloc(LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect) {

	unsigned int _hash = MurmurHash2A("VirtualAlloc", 13, 13);

	temp_VirtualAlloc = (LPVOID(WINAPI*)(LPVOID,
		SIZE_T,
		DWORD,
		DWORD))get_api(_hash, "kernel32.dll", 13, 13);

	return temp_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL hash_VirtualFree(LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  dwFreeType) {

	unsigned int _hash = MurmurHash2A("VirtualFree", 12, 12);

	temp_VirtualFree = (BOOL(WINAPI*)(LPVOID,
		SIZE_T,
		DWORD))get_api(_hash, "kernel32.dll", 12, 12);

	return temp_VirtualFree(lpAddress, dwSize, dwFreeType);
}

