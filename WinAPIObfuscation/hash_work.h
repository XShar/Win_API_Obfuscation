#pragma once
/*
Здесь размещаются прототипы функций, которые из хеша имени функции запустит реальныю функцию
*/
#include <windows.h>
HANDLE hash_CreateFileA(
	__in    LPCSTR      file_name,
	__in    DWORD     access,
	__in    DWORD     share_mode,
	__in    LPSECURITY_ATTRIBUTES security,
	__in    DWORD     creation_disposition,
	__in    DWORD     flags,
	__in HANDLE    template_file);

HMODULE hash_LoadLibraryA(__in LPCSTR file_name);
