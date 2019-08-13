#pragma once
/*
Здесь размещаются прототипы функций, которые из хеша имени функции запустит реальныю функцию
*/
#include <windows.h>
HANDLE hash_CreateFileA(__in LPCSTR file_name, __in DWORD access, __in DWORD share_mode, __in LPSECURITY_ATTRIBUTES security, __in DWORD creation_disposition, __in DWORD flags, __in HANDLE template_file);
BOOL hash_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
LPVOID hash_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL hash_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
LPVOID hash_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL hash_VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DWORD hash_QueryDosDeviceW(LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax);
BOOL hash_GetDiskFreeSpaceExW(LPCWSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller, PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes);
HMODULE hash_LoadLibraryW(LPCWSTR lpLibFileName);
BOOL hash_GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule);
DWORD hash_GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
HMODULE hash_GetModuleHandleA(LPCSTR lpModuleName);
FARPROC hash_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
HMODULE hash_LoadLibraryA(__in LPCSTR file_name);
