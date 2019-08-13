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

LPVOID hash_VirtualAllocEx(HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect) {

	unsigned int _hash = MurmurHash2A("VirtualAllocEx", 15, 15);

	temp_VirtualAllocEx = (LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))get_api(_hash, "kernel32.dll", 15, 15);

	return temp_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL hash_VirtualFreeEx(HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  dwFreeType) {

	unsigned int _hash = MurmurHash2A("VirtualFreeEx", 14, 14);

	temp_VirtualFreeEx = (BOOL(WINAPI*)(HANDLE ,
		LPVOID ,
		SIZE_T ,
		DWORD  ))get_api(_hash, "kernel32.dll", 14, 14);

	return temp_VirtualFreeEx( hProcess,
		 lpAddress,
		 dwSize,
		  dwFreeType);
}

DWORD hash_QueryDosDeviceW(LPCWSTR lpDeviceName,
	LPWSTR  lpTargetPath,
	DWORD   ucchMax) {

	unsigned int _hash = MurmurHash2A("QueryDosDeviceW", 16, 16);

	temp_QueryDosDeviceW = (DWORD(WINAPI*)(LPCWSTR,
		LPWSTR,
		DWORD))get_api(_hash, "kernel32.dll", 16, 16);

	return temp_QueryDosDeviceW( lpDeviceName,
		  lpTargetPath,
		   ucchMax);
}

BOOL hash_GetDiskFreeSpaceExW(LPCWSTR lpDirectoryName,
	PULARGE_INTEGER lpFreeBytesAvailableToCaller,
	PULARGE_INTEGER lpTotalNumberOfBytes,
	PULARGE_INTEGER lpTotalNumberOfFreeBytes) {

	unsigned int _hash = MurmurHash2A("GetDiskFreeSpaceExW", 20, 20);

	temp_GetDiskFreeSpaceExW = (BOOL(WINAPI*)(LPCWSTR ,
		PULARGE_INTEGER ,
		PULARGE_INTEGER ,
		PULARGE_INTEGER ))get_api(_hash, "kernel32.dll", 20, 20);

	return temp_GetDiskFreeSpaceExW( lpDirectoryName,
		 lpFreeBytesAvailableToCaller,
		 lpTotalNumberOfBytes,
		 lpTotalNumberOfFreeBytes);
}
HMODULE hash_LoadLibraryW(LPCWSTR lpLibFileName) {

	unsigned int _hash = MurmurHash2A("LoadLibraryW", 13, 13);

	temp_LoadLibraryW = (HMODULE(WINAPI*)(LPCWSTR))get_api(_hash, "kernel32.dll", 13, 13);

	return temp_LoadLibraryW(lpLibFileName);
}

BOOL hash_GetModuleHandleExW(DWORD   dwFlags,
	LPCWSTR lpModuleName,
	HMODULE* phModule) {

	unsigned int _hash = MurmurHash2A("GetModuleHandleExW", 19, 19);

	temp_GetModuleHandleExW = (BOOL(WINAPI*)(DWORD   ,
		LPCWSTR ,
		HMODULE * ))get_api(_hash, "kernel32.dll", 19, 19);

	return temp_GetModuleHandleExW(   dwFlags,
		 lpModuleName,
		 phModule);
}
DWORD hash_GetModuleFileNameW(HMODULE hModule,
	LPWSTR  lpFilename,
	DWORD   nSize) {

	int lenSeed = 19;
	unsigned int _hash = MurmurHash2A("GetModuleFileNameW", lenSeed, lenSeed);

	temp_GetModuleFileNameW = (DWORD(WINAPI*)(HMODULE ,
		LPWSTR  ,
		DWORD   ))get_api(_hash, "kernel32.dll", lenSeed, lenSeed);

	return temp_GetModuleFileNameW( hModule,
		  lpFilename,
		   nSize);
}