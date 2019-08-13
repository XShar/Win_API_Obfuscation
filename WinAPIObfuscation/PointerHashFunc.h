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