#pragma once
/*
 *В этом заголовочном файле размещаем указатели на функции, которые хотим скрыть (В этом примере рассматривается функция CreateFile)
 * temp_CreateFile - Указатель на функцию CreateFile, адрес которого мы получим в функции get_api(create_file_hash, "Kernel32.dll")
 *
*/
#pragma once
#include <windows.h>
#include <tlhelp32.h>

HANDLE (WINAPI* temp_CreateFile)(__in LPCSTR file_name,
                                 __in DWORD access,
                                 __in DWORD share,
                                 __in LPSECURITY_ATTRIBUTES security,
                                 __in DWORD creation_disposition,
                                 __in DWORD flags,
                                 __in HANDLE template_file) = NULL;

BOOL (WINAPI* temp_VirtualProtect)(LPVOID lpAddress,
                                   SIZE_T dwSize,
                                   DWORD flNewProtect,
                                   PDWORD lpflOldProtect) = NULL;

LPVOID (WINAPI* temp_VirtualAlloc)(LPVOID lpAddress,
                                   SIZE_T dwSize,
                                   DWORD flAllocationType,
                                   DWORD flProtect) = NULL;

BOOL (WINAPI* temp_VirtualFree)(LPVOID lpAddress,
                                SIZE_T dwSize,
                                DWORD dwFreeType) = NULL;

LPVOID (WINAPI* temp_VirtualAllocEx)(HANDLE hProcess,
                                     LPVOID lpAddress,
                                     SIZE_T dwSize,
                                     DWORD flAllocationType,
                                     DWORD flProtect) = NULL;

BOOL (WINAPI* temp_VirtualFreeEx)(HANDLE hProcess,
                                  LPVOID lpAddress,
                                  SIZE_T dwSize,
                                  DWORD dwFreeType) = NULL;


DWORD (WINAPI* temp_QueryDosDeviceW)(LPCWSTR lpDeviceName,
                                     LPWSTR lpTargetPath,
                                     DWORD ucchMax) = NULL;

BOOL (WINAPI* temp_GetDiskFreeSpaceExW)(LPCWSTR lpDirectoryName,
                                        PULARGE_INTEGER lpFreeBytesAvailableToCaller,
                                        PULARGE_INTEGER lpTotalNumberOfBytes,
                                        PULARGE_INTEGER lpTotalNumberOfFreeBytes) = NULL;

HMODULE (WINAPI* temp_LoadLibraryW)(LPCWSTR lpLibFileName) = NULL;

BOOL (WINAPI* temp_GetModuleHandleExW)(DWORD dwFlags,
                                       LPCWSTR lpModuleName,
                                       HMODULE* phModule) = NULL;

DWORD (WINAPI* temp_GetModuleFileNameW)(HMODULE hModule,
                                        LPWSTR lpFilename,
                                        DWORD nSize) = NULL;

HMODULE (WINAPI* temp_GetModuleHandleA)(LPCSTR lpModuleName) = NULL;

FARPROC (WINAPI* temp_GetProcAddress)(HMODULE hModule,
                                      LPCSTR lpProcName) = NULL;

HMODULE (WINAPI* temp_GetModuleHandleW)(LPCWSTR lpModuleName) = NULL;

HANDLE (WINAPI* temp_GetStdHandle)(_In_ DWORD nStdHandle) = NULL;

BOOL (WINAPI* temp_GetConsoleScreenBufferInfo)(_In_ HANDLE hConsoleOutput,
                                               _Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo) = NULL;

BOOL (WINAPI* temp_SetConsoleTextAttribute)(_In_ HANDLE hConsoleOutput,
                                            _In_ WORD wAttributes) = NULL;

DWORD (WINAPI* temp_GetTickCount)() = NULL;

BOOL (WINAPI* temp_VerifyVersionInfoW)(LPOSVERSIONINFOEXA lpVersionInformation,
                                       DWORD dwTypeMask,
                                       DWORDLONG dwlConditionMask) = NULL;

UINT (WINAPI* temp_GetSystemWindowsDirectoryW)(LPWSTR lpBuffer,
                                               UINT uSize) = NULL;

UINT (WINAPI* temp_GetWindowsDirectoryW)(LPWSTR lpBuffer,
                                         UINT uSize) = NULL;

UINT (WINAPI* temp_GetSystemDirectoryW)(LPWSTR lpBuffer,
                                        UINT uSize) = NULL;

UINT (WINAPI* temp_GetSystemDirectoryA)(LPSTR lpBuffer,
                                        UINT uSize) = NULL;

void (WINAPI* temp_GetSystemInfo)(LPSYSTEM_INFO lpSystemInfo) = NULL;

DWORD (WINAPI* temp_ExpandEnvironmentStringsW)(LPCWSTR lpSrc,
                                               LPWSTR lpDst,
                                               DWORD nSize) = NULL;

BOOL (WINAPI* temp_QueryPerformanceCounter)(LARGE_INTEGER* lpPerformanceCount) = NULL;

BOOL (WINAPI* temp_IsProcessorFeaturePresent)(DWORD ProcessorFeature) = NULL;

PVOID (WINAPI* temp_AddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) = NULL;

void (WINAPI* temp_SetLastError)(DWORD dwErrCode) = NULL;

_Post_equals_last_error_ DWORD (WINAPI* temp_GetLastError)() = NULL;

void (WINAPI* temp_OutputDebugStringW)(LPCWSTR lpOutputString) = NULL;

DWORD (WINAPI* temp_FormatMessageW)(DWORD dwFlags,
                                    LPCVOID lpSource,
                                    DWORD dwMessageId,
                                    DWORD dwLanguageId,
                                    LPWSTR lpBuffer,
                                    DWORD nSize,
                                    va_list* Arguments) = NULL;

HANDLE (WINAPI* temp_CreateMutexW)(LPSECURITY_ATTRIBUTES lpMutexAttributes,
                                   BOOL bInitialOwner,
                                   LPCWSTR lpName) = NULL;

HANDLE (WINAPI* temp_CreateEventW)(LPSECURITY_ATTRIBUTES lpEventAttributes,
                                   BOOL bManualReset,
                                   BOOL bInitialState,
                                   LPCWSTR lpName) = NULL;

BOOL (WINAPI* temp_SetEvent)(HANDLE hEvent) = NULL;

DWORD (WINAPI* temp_WaitForSingleObject)(HANDLE hHandle,
                                         DWORD dwMilliseconds) = NULL;

DWORD (WINAPI* temp_QueueUserAPC)(PAPCFUNC pfnAPC,
                                  HANDLE hThread,
                                  ULONG_PTR dwData) = NULL;

HANDLE (WINAPI* temp_CreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                   SIZE_T dwStackSize,
                                   LPTHREAD_START_ROUTINE lpStartAddress,
                                   __drv_aliasesMem LPVOID lpParameter,
                                   DWORD dwCreationFlags,
                                   LPDWORD lpThreadId) = NULL;

HANDLE (WINAPI* temp_CreateWaitableTimerW)(LPSECURITY_ATTRIBUTES lpTimerAttributes,
                                           BOOL bManualReset,
                                           LPCWSTR lpTimerName) = NULL;

BOOL (WINAPI* temp_SetWaitableTimer)(HANDLE hTimer,
                                     const LARGE_INTEGER* lpDueTime,
                                     LONG lPeriod,
                                     PTIMERAPCROUTINE pfnCompletionRoutine,
                                     LPVOID lpArgToCompletionRoutine,
                                     BOOL fResume) = NULL;

BOOL (WINAPI* temp_CancelWaitableTimer)(HANDLE hTimer) = NULL;

BOOL (WINAPI* temp_CreateTimerQueueTimer)(PHANDLE phNewTimer,
                                          HANDLE TimerQueue,
                                          WAITORTIMERCALLBACK Callback,
                                          PVOID DueTime,
                                          DWORD Period,
                                          DWORD Flags,
                                          ULONG Parameter) = NULL;

DWORD (WINAPI* temp_SetFilePointer)(HANDLE hFile,
                                    LONG lDistanceToMove,
                                    PLONG lpDistanceToMoveHigh,
                                    DWORD dwMoveMethod) = NULL;

BOOL (WINAPI* temp_ReadFile)(HANDLE hFile,
                             LPVOID lpBuffer,
                             DWORD nNumberOfBytesToRead,
                             LPDWORD lpNumberOfBytesRead,
                             LPOVERLAPPED lpOverlapped) = NULL;

HANDLE (WINAPI* temp_CreateFileW)(LPCWSTR lpFileName,
                                  DWORD dwDesiredAccess,
                                  DWORD dwShareMode,
                                  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                  DWORD dwCreationDisposition,
                                  DWORD dwFlagsAndAttributes,
                                  HANDLE hTemplateFile) = NULL;

DWORD (WINAPI* temp_GetFullPathNameW)(LPCWSTR lpFileName,
                                      DWORD nBufferLength,
                                      LPWSTR lpBuffer,
                                      LPWSTR* lpFilePart) = NULL;

DWORD (WINAPI* temp_GetFileAttributesW)(LPCWSTR lpFileName) = NULL;

void (WINAPI* temp_GetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime) = NULL;

SIZE_T (WINAPI* temp_VirtualQuery)(LPCVOID lpAddress,
                                   PMEMORY_BASIC_INFORMATION lpBuffer,
                                   SIZE_T dwLength) = NULL;

BOOL (WINAPI* temp_ReadProcessMemory)(HANDLE hProcess,
                                      LPCVOID lpBaseAddress,
                                      LPVOID lpBuffer,
                                      SIZE_T nSize,
                                      SIZE_T* lpNumberOfBytesRead) = NULL;

/*DECLSPEC_ALLOCATOR*/
HLOCAL (WINAPI* temp_LocalAlloc)(UINT uFlags,
                                 SIZE_T uBytes) = NULL;

HLOCAL (WINAPI* temp_LocalFree)(_Frees_ptr_opt_ HLOCAL hMem) = NULL;

BOOL (WINAPI* temp_GlobalMemoryStatusEx)(LPMEMORYSTATUSEX lpBuffer) = NULL;

BOOL (WINAPI* temp_WriteProcessMemory)(HANDLE hProcess,
                                       LPVOID lpBaseAddress,
                                       LPCVOID lpBuffer,
                                       SIZE_T nSize,
                                       SIZE_T* lpNumberOfBytesWritten) = NULL;

SIZE_T (WINAPI* temp_LocalSize)(HLOCAL hMem) = NULL;

LPVOID (WINAPI* temp_HeapAlloc)(HANDLE hHeap,
                                DWORD dwFlags,
                                SIZE_T dwBytes) = NULL;

HANDLE (WINAPI* temp_GetProcessHeap)() = NULL;
BOOL (WINAPI* temp_HeapFree)(HANDLE hHeap,
                             DWORD dwFlags,
                             _Frees_ptr_opt_ LPVOID lpMem) = NULL;

BOOL (WINAPI* temp_IsBadReadPtr)(const VOID* lp,
                                 UINT_PTR ucb) = NULL;
HANDLE (WINAPI* temp_GetCurrentProcess)() = NULL;

BOOL (WINAPI* temp_GetThreadContext)(HANDLE hThread,
                                     LPCONTEXT lpContext) = NULL;

void (WINAPI* temp_Sleep)(DWORD dwMilliseconds) = NULL;

DWORD (WINAPI* temp_GetCurrentProcessId)() = NULL;

HANDLE (WINAPI* temp_OpenProcess)(DWORD dwDesiredAccess,
                                  BOOL bInheritHandle,
                                  DWORD dwProcessId) = NULL;

DWORD (WINAPI* temp_GetEnvironmentVariableW)(LPCWSTR lpName,
                                             LPWSTR lpBuffer,
                                             DWORD nSize) = NULL;

HANDLE (WINAPI* temp_CreateToolhelp32Snapshot)(DWORD dwFlags,
                                               DWORD th32ProcessID) = NULL;

BOOL (WINAPI* temp_Module32FirstW)(HANDLE hSnapshot,
                                   LPMODULEENTRY32W lpme) = NULL;

BOOL (WINAPI* temp_Module32NextW)(HANDLE hSnapshot,
                                  LPMODULEENTRY32W lpme) = NULL;

BOOL (WINAPI* temp_SwitchToThread)() = NULL;

BOOL (WINAPI* temp_IsWow64Process)(HANDLE hProcess,
                                   PBOOL Wow64Process) = NULL;

HANDLE (WINAPI* temp_CreateRemoteThread)(HANDLE hProcess,
                                         LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                         SIZE_T dwStackSize,
                                         LPTHREAD_START_ROUTINE lpStartAddress,
                                         LPVOID lpParameter,
                                         DWORD dwCreationFlags,
                                         LPDWORD lpThreadId) = NULL;

BOOL (WINAPI* temp_Thread32First)(HANDLE hSnapshot,
                                  LPTHREADENTRY32 lpte) = NULL;

HANDLE (WINAPI* temp_OpenThread)(DWORD dwDesiredAccess,
                                 BOOL bInheritHandle,
                                 DWORD dwThreadId) = NULL;

BOOL (WINAPI* temp_Thread32Next)(HANDLE hSnapshot,
                                 LPTHREADENTRY32 lpte) = NULL;

BOOL (WINAPI* temp_Process32FirstW)(HANDLE hSnapshot,
                                    LPTHREADENTRY32 lpte) = NULL;

BOOL (WINAPI* temp_Process32NextW)(HANDLE hSnapshot,
                                   LPTHREADENTRY32 lpte) = NULL;

DWORD (WINAPI* temp_GetCurrentThreadId)() = NULL;


BOOL (WINAPI* temp_TerminateProcess)(HANDLE hProcess,
                                     UINT uExitCode) = NULL;


BOOL (WINAPI* temp_CloseHandle)(HANDLE hObject) = NULL;

BOOL (WINAPI* temp_DuplicateHandle)(HANDLE hSourceProcessHandle,
                                    HANDLE hSourceHandle,
                                    HANDLE hTargetProcessHandle,
                                    LPHANDLE lpTargetHandle,
                                    DWORD dwDesiredAccess,
                                    BOOL bInheritHandle,
                                    DWORD dwOptions) = NULL;


BOOL (WINAPI* temp_SetHandleInformation)(HANDLE hObject,
                                         DWORD dwMask,
                                         DWORD dwFlags) = NULL;

BOOL (WINAPI* temp_DeviceIoControl)(HANDLE hDevice,
                                    DWORD dwIoControlCode,
                                    LPVOID lpInBuffer,
                                    DWORD nInBufferSize,
                                    LPVOID lpOutBuffer,
                                    DWORD nOutBufferSize,
                                    LPDWORD lpBytesReturned,
                                    LPOVERLAPPED lpOverlapped) = NULL;

int (WINAPI* temp_lstrlenW)(LPCWSTR lpString) = NULL;

int (WINAPI* temp_MultiByteToWideChar)(UINT CodePage,
                                       DWORD dwFlags,
                                       _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
                                       int cbMultiByte,
                                       LPWSTR lpWideCharStr,
                                       int cchWideChar) = NULL;

HANDLE (WINAPI* temp_CreateTimerQueue)() = NULL;

BOOL (WINAPI* temp_DeleteTimerQueueEx)(HANDLE TimerQueue,
                                       HANDLE CompletionEvent) = NULL;

BOOL (WINAPI* temp_CheckRemoteDebuggerPresent)(HANDLE hProcess,
                                               PBOOL pbDebuggerPresent) = NULL;

LONG (WINAPI* temp_UnhandledExceptionFilter)(_EXCEPTION_POINTERS* ExceptionInfo) = NULL;

LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI* temp_SetUnhandledExceptionFilter)(
	LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) = NULL;

ULONG (WINAPI* temp_RemoveVectoredExceptionHandler)(PVOID Handle) = NULL;
