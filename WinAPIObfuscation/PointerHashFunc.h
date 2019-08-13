#pragma once
/*
 *В этом заголовочном файле размещаем указатели на функции, которые хотим скрыть (В этом примере рассматривается функция CreateFile)
 * temp_CreateFile - Указатель на функцию CreateFile, адрес которого мы получим в функции get_api(create_file_hash, "Kernel32.dll")
 *
*/
#pragma once
#include <windows.h>
HANDLE(WINAPI* temp_CreateFile)(__in LPCSTR file_name,
	__in DWORD access,
	__in DWORD share,
	__in LPSECURITY_ATTRIBUTES security,
	__in DWORD creation_disposition,
	__in DWORD flags,
	__in HANDLE template_file) = NULL;

BOOL(WINAPI* temp_VirtualProtect)(LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect) = NULL;

LPVOID(WINAPI* temp_VirtualAlloc)(LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect) = NULL;

BOOL(WINAPI* temp_VirtualFree)(LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  dwFreeType) = NULL;

LPVOID(WINAPI* temp_VirtualAllocEx)(HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect) = NULL;

BOOL(WINAPI* temp_VirtualFreeEx)(HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  dwFreeType) = NULL;


DWORD(WINAPI* temp_QueryDosDeviceW)(LPCWSTR lpDeviceName,
	LPWSTR  lpTargetPath,
	DWORD   ucchMax) = NULL;

BOOL(WINAPI* temp_GetDiskFreeSpaceExW)(LPCWSTR lpDirectoryName,
	PULARGE_INTEGER lpFreeBytesAvailableToCaller,
	PULARGE_INTEGER lpTotalNumberOfBytes,
	PULARGE_INTEGER lpTotalNumberOfFreeBytes) = NULL;

HMODULE(WINAPI* temp_LoadLibraryW)(LPCWSTR lpLibFileName) = NULL;
BOOL(WINAPI* temp_GetModuleHandleExW)(DWORD   dwFlags,
	LPCWSTR lpModuleName,
	HMODULE* phModule) = NULL;
DWORD(WINAPI* temp_GetModuleFileNameW)(HMODULE hModule,
	LPWSTR  lpFilename,
	DWORD   nSize) = NULL;

HMODULE(WINAPI* temp_GetModuleHandleA)(LPCSTR lpModuleName) = NULL;

FARPROC(WINAPI* temp_GetProcAddress)(HMODULE hModule,
	LPCSTR  lpProcName) = NULL;