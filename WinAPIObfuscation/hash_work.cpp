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

HMODULE hash_GetModuleHandleA(LPCSTR lpModuleName) {

	unsigned int _hash = MurmurHash2A("GetModuleHandleA", 17, 17);

	temp_GetModuleHandleA = (HMODULE(WINAPI*)(LPCSTR))get_api(_hash, "kernel32.dll", 17, 17);

	return temp_GetModuleHandleA(lpModuleName);
}
HMODULE hash_GetModuleHandleW(LPCWSTR lpModuleName) {

	unsigned int _hash = MurmurHash2A("GetModuleHandleW", 17, 17);

	temp_GetModuleHandleW = (HMODULE(WINAPI*)(LPCWSTR))get_api(_hash, "kernel32.dll", 17, 17);

	return temp_GetModuleHandleW(lpModuleName);
}
FARPROC hash_GetProcAddress(HMODULE hModule,
	LPCSTR  lpProcName) {

	unsigned int _hash = MurmurHash2A("GetProcAddress", 15, 15);

	temp_GetProcAddress = (FARPROC(WINAPI*)(HMODULE ,
		LPCSTR  ))get_api(_hash, "kernel32.dll", 15, 15);

	return temp_GetProcAddress( hModule,
		  lpProcName);
}
HANDLE hash_GetStdHandle(_In_ DWORD nStdHandle) {

	unsigned int _hash = MurmurHash2A("GetStdHandle", 13, 13);

	temp_GetStdHandle = (HANDLE(WINAPI*)(_In_ DWORD ))get_api(_hash, "kernel32.dll", 13, 13);

	return temp_GetStdHandle( nStdHandle);
}
BOOL hash_GetConsoleScreenBufferInfo(_In_  HANDLE                      hConsoleOutput,
	_Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo) {

	unsigned int _hash = MurmurHash2A("GetConsoleScreenBufferInfo", 27, 27);

	temp_GetConsoleScreenBufferInfo = (BOOL(WINAPI*)(_In_  HANDLE                      ,
		_Out_ PCONSOLE_SCREEN_BUFFER_INFO ))get_api(_hash, "kernel32.dll", 27, 27);

	return temp_GetConsoleScreenBufferInfo(hConsoleOutput,
		 lpConsoleScreenBufferInfo);
}
BOOL hash_SetConsoleTextAttribute(_In_ HANDLE hConsoleOutput,
	_In_ WORD   wAttributes) {

	unsigned int _hash = MurmurHash2A("SetConsoleTextAttribute", 24, 24);

	temp_SetConsoleTextAttribute = (BOOL(WINAPI*)(_In_ HANDLE ,
		_In_ WORD   ))get_api(_hash, "kernel32.dll", 24, 24);

	return temp_SetConsoleTextAttribute( hConsoleOutput,
		   wAttributes);
}
DWORD hash_GetTickCount() {

	int lenSeed = 13;
	unsigned int _hash = MurmurHash2A("GetTickCount", lenSeed, lenSeed);

	temp_GetTickCount = (DWORD(WINAPI*)())get_api(_hash, "kernel32.dll", lenSeed, lenSeed);

	return temp_GetTickCount();
}
BOOL hash_VerifyVersionInfoW(LPOSVERSIONINFOEXA lpVersionInformation,
	DWORD              dwTypeMask,
	DWORDLONG          dwlConditionMask) {

	int lenSeed = 18;
	unsigned int _hash = MurmurHash2A("VerifyVersionInfoW", lenSeed, lenSeed);

	temp_VerifyVersionInfoW = (BOOL(WINAPI*)(LPOSVERSIONINFOEXA ,
		DWORD              ,
		DWORDLONG          ))get_api(_hash, "kernel32.dll", lenSeed, lenSeed);

	return temp_VerifyVersionInfoW( lpVersionInformation,
		              dwTypeMask,
		          dwlConditionMask);
}
UINT hash_GetSystemWindowsDirectoryW(LPWSTR lpBuffer,
	UINT   uSize) {

	int lenSeed = 27;
	unsigned int _hash = MurmurHash2A("GetSystemWindowsDirectoryW", lenSeed, lenSeed);

	temp_GetSystemWindowsDirectoryW = (UINT(WINAPI*)(LPWSTR ,
		UINT   ))get_api(_hash, "kernel32.dll", lenSeed, lenSeed);

	return temp_GetSystemWindowsDirectoryW( lpBuffer,
		   uSize);
}
UINT hash_GetWindowsDirectoryW(LPWSTR lpBuffer,
	UINT   uSize) {

	int lenSeed = 21;
	unsigned int _hash = MurmurHash2A("GetWindowsDirectoryW", lenSeed, lenSeed);

	temp_GetWindowsDirectoryW = (UINT(WINAPI*)(LPWSTR,
		UINT))get_api(_hash, "kernel32.dll", lenSeed, lenSeed);

	return temp_GetWindowsDirectoryW(lpBuffer,
		uSize);
}
UINT hash_GetSystemDirectoryW(LPWSTR lpBuffer,
	UINT   uSize) {

	int lenSeed = 20;
	unsigned int _hash = MurmurHash2A("GetSystemDirectoryW", lenSeed, lenSeed);

	temp_GetSystemDirectoryW = (UINT(WINAPI*)(LPWSTR,
		UINT))get_api(_hash, "kernel32.dll", lenSeed, lenSeed);

	return temp_GetSystemDirectoryW(lpBuffer,
		uSize);
}
UINT hash_GetSystemDirectoryA(LPSTR lpBuffer,
	UINT   uSize) {

	int lenSeed = 20;
	unsigned int _hash = MurmurHash2A("GetSystemDirectoryA", lenSeed, lenSeed);

	temp_GetSystemDirectoryA = (UINT(WINAPI*)(LPSTR,
		UINT))get_api(_hash, "kernel32.dll", lenSeed, lenSeed);

	return temp_GetSystemDirectoryA(lpBuffer,
		uSize);
}
void hash_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo) {

	int lenSeed = 14;
	unsigned int _hash = MurmurHash2A("GetSystemInfo", lenSeed, lenSeed);

	temp_GetSystemInfo = (void(WINAPI*)(LPSYSTEM_INFO ))get_api(_hash, "kernel32.dll", lenSeed, lenSeed);

	return temp_GetSystemInfo( lpSystemInfo);
}