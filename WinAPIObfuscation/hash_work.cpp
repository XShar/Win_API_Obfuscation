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

	//Хешируем "CreateFile"
	unsigned int create_file_hash = MurmurHash2A("CreateFileA", 12, 12);

	temp_CreateFile = (HANDLE(WINAPI*)(LPCSTR,
		DWORD,
		DWORD,
		LPSECURITY_ATTRIBUTES,
		DWORD,
		DWORD,
		HANDLE))get_api(create_file_hash, "kernel32.dll", 12, 12);

	return temp_CreateFile(file_name, access, share_mode, security, creation_disposition, flags, template_file);
}
