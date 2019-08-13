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

HMODULE(WINAPI* temp_GetModuleHandleW)(LPCWSTR lpModuleName) = NULL;

HANDLE(WINAPI* temp_GetStdHandle)(_In_ DWORD nStdHandle) = NULL;

BOOL(WINAPI* temp_GetConsoleScreenBufferInfo)(_In_  HANDLE                      hConsoleOutput,
	_Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo) = NULL;

BOOL(WINAPI* temp_SetConsoleTextAttribute)(_In_ HANDLE hConsoleOutput,
	_In_ WORD   wAttributes) = NULL;

DWORD(WINAPI* temp_GetTickCount)() = NULL;

BOOL(WINAPI* temp_VerifyVersionInfoW)(LPOSVERSIONINFOEXA lpVersionInformation,
	DWORD              dwTypeMask,
	DWORDLONG          dwlConditionMask) = NULL;

UINT(WINAPI* temp_GetSystemWindowsDirectoryW)(LPWSTR lpBuffer,
	UINT   uSize) = NULL;

UINT(WINAPI* temp_GetWindowsDirectoryW)(LPWSTR lpBuffer,
	UINT   uSize) = NULL;

UINT(WINAPI* temp_GetSystemDirectoryW)(LPWSTR lpBuffer,
	UINT   uSize) = NULL;

UINT(WINAPI* temp_GetSystemDirectoryA)(LPSTR lpBuffer,
	UINT   uSize) = NULL;

void(WINAPI* temp_GetSystemInfo)(LPSYSTEM_INFO lpSystemInfo) = NULL;

DWORD(WINAPI* temp_ExpandEnvironmentStringsW)(LPCWSTR lpSrc,
	LPWSTR  lpDst,
	DWORD   nSize) = NULL;

BOOL(WINAPI* temp_QueryPerformanceCounter)(LARGE_INTEGER *lpPerformanceCount) = NULL;

BOOL(WINAPI* temp_IsProcessorFeaturePresent)(DWORD ProcessorFeature) = NULL;

PVOID(WINAPI* temp_AddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) = NULL;

void(WINAPI* temp_SetLastError)(DWORD dwErrCode) = NULL;

_Post_equals_last_error_ DWORD(WINAPI* temp_GetLastError)() = NULL;

void(WINAPI* temp_OutputDebugStringW)(LPCWSTR lpOutputString) = NULL;

DWORD(WINAPI* temp_FormatMessageW)(DWORD   dwFlags,
	LPCVOID lpSource,
	DWORD   dwMessageId,
	DWORD   dwLanguageId,
	LPWSTR  lpBuffer,
	DWORD   nSize,
	va_list* Arguments) = NULL;

HANDLE(WINAPI* temp_CreateMutexW)(LPSECURITY_ATTRIBUTES lpMutexAttributes,
	BOOL                  bInitialOwner,
	LPCWSTR               lpName) = NULL;

HANDLE(WINAPI* temp_CreateEventW)(LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL                  bManualReset,
	BOOL                  bInitialState,
	LPCWSTR               lpName) = NULL;

BOOL(WINAPI* temp_SetEvent)(HANDLE hEvent) = NULL;

DWORD(WINAPI* temp_WaitForSingleObject)(HANDLE hHandle,
	DWORD  dwMilliseconds) = NULL;

DWORD(WINAPI* temp_QueueUserAPC)(PAPCFUNC  pfnAPC,
	HANDLE    hThread,
	ULONG_PTR dwData) = NULL;

HANDLE(WINAPI* temp_CreateThread)(LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId) = NULL;

HANDLE(WINAPI* temp_CreateWaitableTimerW)(LPSECURITY_ATTRIBUTES lpTimerAttributes,
	BOOL                  bManualReset,
	LPCWSTR               lpTimerName) = NULL;

BOOL(WINAPI* temp_SetWaitableTimer)(HANDLE              hTimer,
	const LARGE_INTEGER* lpDueTime,
	LONG                lPeriod,
	PTIMERAPCROUTINE    pfnCompletionRoutine,
	LPVOID              lpArgToCompletionRoutine,
	BOOL                fResume) = NULL;

BOOL(WINAPI* temp_CancelWaitableTimer)(HANDLE hTimer) = NULL;

BOOL(WINAPI* temp_CreateTimerQueueTimer)(PHANDLE             phNewTimer,
	HANDLE              TimerQueue,
	WAITORTIMERCALLBACK Callback,
	PVOID               DueTime,
	DWORD               Period,
	DWORD               Flags,
	ULONG               Parameter) = NULL;

DWORD(WINAPI* temp_SetFilePointer)(HANDLE hFile,
	LONG   lDistanceToMove,
	PLONG  lpDistanceToMoveHigh,
	DWORD  dwMoveMethod) = NULL;

BOOL(WINAPI* temp_ReadFile)(HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped) = NULL;

HANDLE(WINAPI* temp_CreateFileW)(LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile) = NULL;

DWORD(WINAPI* temp_GetFullPathNameW)(LPCWSTR lpFileName,
	DWORD   nBufferLength,
	LPWSTR  lpBuffer,
	LPWSTR* lpFilePart) = NULL;

DWORD(WINAPI* temp_GetFileAttributesW)(LPCWSTR lpFileName) = NULL;

void(WINAPI* temp_GetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime) = NULL;