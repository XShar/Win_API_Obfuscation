#pragma once
#define _WIN32_WINNT 0x0400
#include <consoleapi2.h>
#include <synchapi.h>
#include <cstdio>
#include "C.h"
#include <winbase.h>

DWORD WINAPI thread_function(LPVOID lpParameter)
{
	while (true)
	{
		SleepEx(INFINITE, TRUE);
	}
}

VOID CALLBACK apc_function_1(ULONG_PTR dwParam)
{
	C* obj = (C*)dwParam;
	obj->do_something();
}

typedef struct _MYDATA
{
	TCHAR* szText;
	DWORD dwValue;
} MYDATA;

VOID CALLBACK TimerAPCProc(
	LPVOID lpArg, // Data value.
	DWORD dwTimerLowValue, // Timer low value.
	DWORD dwTimerHighValue)
{
	// Timer high value.

	/*MYDATA* pMyData = (MYDATA*)lpArg;

	printf("Message: %s\nValue: %d\n\n", pMyData->szText,
		pMyData->dwValue);*/
	//MessageBeep(0);
}

HANDLE gDoneEvent;

VOID CALLBACK TimerRoutine(PVOID lpParam, BOOLEAN TimerOrWaitFired)
{
	if (lpParam == NULL)
	{
		printf("TimerRoutine lpParam is NULL\n");
	}
	else
	{
		// lpParam points to the argument; in this case it is an int

		printf("Timer routine called. Parameter is %d.\n",
		       *(int*)lpParam);
		if (TimerOrWaitFired)
		{
			printf("The wait timed out.\n");
		}
		else
		{
			printf("The wait event was signaled.\n");
		}
	}

	SetEvent(gDoneEvent);
}

#define WINDOWS_7_BLOCK 0x7DF74744

typedef struct _VECTORED_NODE
{
	_VECTORED_NODE* NextNode;
	_VECTORED_NODE* PrevNode;
	BOOL IsAllocated;
	PVOID EncodedHandler;
} VECTORED_NODE, *PVECTORED_NODE;

typedef struct _RTL_BLOCK
{
	PVOID Unknown;
	PVECTORED_NODE ExceptionList;
} RTL_BLOCK, *PRTL_BLOCK;

LONG CALLBACK TopLevelHandler(EXCEPTION_POINTERS* info)
{
	if (info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		//std::cout << "Yep, caught" << std::endl;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

inline void log()
{
}

template <typename First, typename ...Rest>
void log(First&& message, Rest&& ...rest)
{
	std::cout << std::forward<First>(message) << std::endl;
	log(std::forward<Rest>(rest)...);
}

HANDLE event;

typedef int (WINAPI* ShellAboutProc)(HWND, LPCSTR, LPCSTR, HICON);
