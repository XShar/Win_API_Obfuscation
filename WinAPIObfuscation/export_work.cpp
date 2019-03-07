﻿#include "pch.h"
#include "MurmurHash2A.h"
#include "hash_work.h"
#include "export_work.h"

/*
Для запуска функции LoadLibraryA из хеша, её выносить в модуль hash_work нестал, т.к. это нужно в этом модуле
*/

static HMODULE (WINAPI *temp_LoadLibraryA)(__in LPCSTR file_name) = NULL;
static HMODULE hash_LoadLibraryA(__in LPCSTR file_name) {
	return temp_LoadLibraryA(file_name);
}

static LPVOID parse_export_table(HMODULE module, DWORD api_hash, int len, unsigned int seed) {

	PIMAGE_DOS_HEADER     img_dos_header;
	PIMAGE_NT_HEADERS     img_nt_header;
	PIMAGE_EXPORT_DIRECTORY     in_export;

	img_dos_header = (PIMAGE_DOS_HEADER)module;
	img_nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)img_dos_header + img_dos_header->e_lfanew);
	in_export = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)img_dos_header + img_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD rva_name;
	PWORD rva_ordinal;

	rva_name = (PDWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfNames);
	rva_ordinal = (PWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfNameOrdinals);

	UINT ord = -1;
	char *api_name;
	unsigned int i;

	for (i = 0; i < in_export->NumberOfNames - 1; i++) {

		api_name = (PCHAR)((DWORD_PTR)img_dos_header + rva_name[i]);

		int get_hash = MurmurHash2A(api_name, len, seed);
		
		if (api_hash == get_hash) {
			ord = (UINT)rva_ordinal[i];
			break;
		}

	}

	PDWORD func_addr = (PDWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfFunctions);
	LPVOID func_find = (LPVOID)((DWORD_PTR)img_dos_header + func_addr[ord]);

	return func_find;
}

LPVOID get_api(DWORD api_hash, LPCSTR module, int len, unsigned int seed) {
	HMODULE krnl32, hDll;
	LPVOID  api_func;

#ifdef _WIN64
	int ModuleList = 0x18;
	int ModuleListFlink = 0x18;
	int KernelBaseAddr = 0x10;
	INT_PTR peb = __readgsqword(0x60);
#else
	int ModuleList = 0x0C;
	int ModuleListFlink = 0x10;
	int KernelBaseAddr = 0x10;
	INT_PTR peb = __readfsdword(0x30);
#endif

	// Теперь получим адрес kernel32.dll

	INT_PTR mdllist = *(INT_PTR*)(peb + ModuleList);
	INT_PTR mlink = *(INT_PTR*)(mdllist + ModuleListFlink);
	INT_PTR krnbase = *(INT_PTR*)(mlink + KernelBaseAddr);

	LDR_MODULE *mdl = (LDR_MODULE*)mlink;
	do
	{
		mdl = (LDR_MODULE*)mdl->e[0].Flink;

		if (mdl->base != NULL)
		{
			if (!lstrcmpiW(mdl->dllname.Buffer, L"kernel32.dll")) //сравниваем имя библиотеки в буфере с необходимым
			{
				break;
			}
		}
	} while (mlink != (INT_PTR)mdl);

	krnl32 = (HMODULE)mdl->base;

	//Получаем адрес функции LoadLibraryA 
	int api_hash_LoadLibraryA = MurmurHash2A("LoadLibraryA", 12, 10);
	temp_LoadLibraryA = (HMODULE(WINAPI *)(LPCSTR))parse_export_table(krnl32, api_hash_LoadLibraryA, 12, 10);
	hDll = hash_LoadLibraryA(module);
	
	api_func = (LPVOID)parse_export_table(hDll, api_hash, len, seed);
	return api_func;
}