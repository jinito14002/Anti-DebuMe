/*

Author: jinito14002 (https://github.com/jinito14002)
References: https://anti-debug.checkpoint.com/techniques/debug-flags.html
			https://github.com/LordNoteworthy/al-khaser
			https://github.com/vxunderground/VX-API

*/

#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include "Structures.h" //  "PROCESSINFOCLASS" & "PEB" 

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define BLACKLISTARRAY_SIZE			 6    // Number of elements inside the array
#define YES	"Yes"
#define NO	"No"

WCHAR* g_BlackListedDebuggers[BLACKLISTARRAY_SIZE] = {
		L"x64dbg.exe",                 // xdbg debugger	
		L"x32dbg.exe",                 // xdbg debugger	
		L"ida.exe",                    // IDA disassembler
		L"ida64.exe",                  // IDA disassembler
		L"VsDebugConsole.exe",         // Visual Studio debugger	
		L"msvsmon.exe"                 // Visual Studio debugger
};

typedef NTSTATUS(WINAPI* fnNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
);

BOOL IsDebuggerPresentCheck() {

	printf(
		"IsDebuggerPresent WinAPI function returns TRUE if a debugger is attached to the calling process or FALSE if there isn't. \n\n"
		"Is is supported by ScyllaHide?: %s \n",
		YES
	);

    if (IsDebuggerPresent()) {
        return TRUE;
    }
	
    return FALSE;
}

BOOL IsDebuggerPresentCheck2(PPEB pPeb) {

	printf(
		"Retrieve the DeingDebugged flag manually from PEB structure. \n\n"
		"Is is supported by ScyllaHide?: %s \n",
		YES
	);

    // Checking if the 'BeingDebugged' element is set
    if (pPeb->BeingDebugged == 1)
        return TRUE;

    return FALSE;
}

BOOL IsDebuggerPresentCheck3(PPEB pPeb) {

	printf(
		"Normally, when a process is not being debugged, the NtGlobalFlag field in PEB structure contains the value 0x0. \n"
		"When the process is being debugged, the field will usually contain the value 0x70 indicating these flags are set. \n"
		"Flag				Value \n"
		"FLG_HEAP_ENABLE_TAIL_CHECK	0x10 \n"
		"FLG_HEAP_ENABLE_FREE_CHECK	0x20 \n"
		"FLG_HEAP_VALIDATE_PARAMETERS	0x40 \n"
		"Total				0x70 \n"
		"It will only contain 0x70 if the process is created by the debugger, not if it was attached after execution. \n\n"
		"Is is supported by ScyllaHide?: %s \n",
		YES
	);

    // checking the 'NtGlobalFlag' element
    if (pPeb->NtGlobalFlag == (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS))
        return TRUE;

    return FALSE;
}

BOOL NtQueryInfoProcCheck() {

	printf(
		"NtQueryInformationProcess syscall can be used to detect debuggers with the ProcessDebugPort, ProcessDebugFlags, and ProcessDebugObjectHandle flags. \n"
		"The function returns TRUE if NtQueryInformationProcess returns a valid handle using both ProcessDebugPortand ProcessDebugObjectHandle flags. \n\n"
		"Is is supported by ScyllaHide?: %s \n",
		YES
	);

	NTSTATUS                      STATUS = NULL;
	fnNtQueryInformationProcess   pNtQueryInformationProcess = NULL;
	DWORD64                       dwIsDebuggerPresent = NULL;
	DWORD64                       hProcessDebugObject = NULL;

	// Getting NtQueryInformationProcess address
	pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		printf("\tGetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calling NtQueryInformationProcess with the 'ProcessDebugPort' flag
	STATUS = pNtQueryInformationProcess(
		GetCurrentProcess(),
		ProcessDebugPort,
		&dwIsDebuggerPresent,
		sizeof(DWORD64),
		NULL
	);
	if (STATUS != 0x0) {
		printf("\tNtQueryInformationProcess [1] Failed With Status : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	// If NtQueryInformationProcess returned a non-zero value, the handle is valid, which means we are being debugged
	if (dwIsDebuggerPresent != NULL) {
		// detected a debugger
		return TRUE;
	}

	// Calling NtQueryInformationProcess with the 'ProcessDebugFlags' flag
	DWORD dwProcessDebugFlags, dwReturned;
	const DWORD ProcessDebugFlags = 0x1f;
	STATUS = pNtQueryInformationProcess(
		GetCurrentProcess(),
		ProcessDebugFlags,
		&dwProcessDebugFlags,
		sizeof(DWORD),
		&dwReturned);
	if (STATUS != 0x0) {
		printf("\tNtQueryInformationProcess [2] Failed With Status : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	if (dwProcessDebugFlags == 0) {
		// detected a debugger
		return TRUE;
	}

	// Calling NtQueryInformationProcess with the 'ProcessDebugObjectHandle' flag
	STATUS = pNtQueryInformationProcess(
		GetCurrentProcess(),
		ProcessDebugObjectHandle,
		&hProcessDebugObject,
		sizeof(DWORD64),
		NULL
	);
	// If STATUS is not 0 and not 0xC0000353 (that is 'STATUS_PORT_NOT_SET')
	if (STATUS != 0x0 && STATUS != 0xC0000353) {
		printf("\tNtQueryInformationProcess [3] Failed With Status : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	// If NtQueryInformationProcess returned a non-zero value, the handle is valid, which means we are being debugged
	if (hProcessDebugObject != NULL) {
		// detected a debugger
		return TRUE;
	}

	return FALSE;
}

BOOL HardwareBpCheck() {

	printf(
		"Hardware breakpoints are a feature of modern microprocessors and are implemented in the processor itself. \n"
		"When Hardware breakpoints are set during debugging, it saves the address in Dr0, Dr1, Dr2, and Dr3 registers. \n\n"
		"Is is supported by ScyllaHide?: %s \n",
		YES
	);

	CONTEXT Ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	// Obtain Context structure that contains the registers
	if (!GetThreadContext(GetCurrentThread(), &Ctx)) {
		printf("\tGetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Checks if any values are in Dr registers
	if (Ctx.Dr0 != NULL || Ctx.Dr1 != NULL || Ctx.Dr2 != NULL || Ctx.Dr3 != NULL)
		return TRUE;

	return FALSE;
}

BOOL BlackListCheck() {

	printf(
		"Check the names of the currently running processes against a list of known debugger names. \n\n"
		"Is is supported by ScyllaHide?: %s \n",
		YES
	);

	HANDLE				hSnapShot = NULL;
	PROCESSENTRY32W		ProcEntry = { .dwSize = sizeof(PROCESSENTRY32W) };
	BOOL				bSTATE = FALSE;

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\tCreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}
	if (!Process32FirstW(hSnapShot, &ProcEntry)) {
		printf("\tProcess32FirstW Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}
	do {
		// Loops through the 'g_BlackListedDebuggers' array and comparing each element to the 
		// Current process name captured from the snapshot 
		for (int i = 0; i < BLACKLISTARRAY_SIZE; i++) {
			if (wcscmp(ProcEntry.szExeFile, g_BlackListedDebuggers[i]) == 0) {
				// Debugger detected	
				wprintf(L"\tFound \"%s\" Of Pid : %d \n", ProcEntry.szExeFile, ProcEntry.th32ProcessID);
				bSTATE = TRUE;
				break;
			}
		}
	} while (Process32Next(hSnapShot, &ProcEntry));

_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	return bSTATE;
}

BOOL GetTickCountCheck() {

	printf(
		"Check for debugger based on program execution time using GetTickCount (miliseconds). \n"
		"It retrieves the number of milliseconds that have elapsed since the system was started. \n"
		"Calculating the time difference between two GetTickCount64 can indicate whether the malware is being debugged. \n"
		"GetTickCount can retrieve up to 49.7 days. \n"
		"GetTickCount64 can retrieve more than 49.7 days. \n\n"
		"Is is supported by ScyllaHide?: %s \n",
		YES
	);
	
	ULONGLONG	dwTime1 = NULL,
				dwTime2 = NULL;

	dwTime1 = GetTickCount64();
	// Sleep for 10 miliseconds
	Sleep(10);
	dwTime2 = GetTickCount64();

	printf("\t(Time2 - Time1) : %d \n", (dwTime2 - dwTime1));
	// 50 miliseconds
	if ((dwTime2 - dwTime1) > 50) {
		return TRUE;
	}
	return FALSE;
}

BOOL QueryPerformanceCounterCheck() {

	printf(
		"Check for debugger based on program execution time using QueryPerformanceCounter (nanoseconds). \n"
		"It reads the performance counter and returns the total number of ticks that have occurred since the system was started. \n"
		"Returns a number of counts / ticks per second. \n\n"
		"Is is supported by ScyllaHide?: %s \n",
		YES
	);

	LARGE_INTEGER	Time1 = { 0 },
					Time2 = { 0 };

	if (!QueryPerformanceCounter(&Time1)) {
		printf("\tQueryPerformanceCounter [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Sleep for 10 miliseconds
	Sleep(10);

	if (!QueryPerformanceCounter(&Time2)) {
		printf("\tQueryPerformanceCounter [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("\t(Time2 - Time1) : %d \n", (Time2.QuadPart - Time1.QuadPart));

	// If the difference is larger than 500,000 counts
	if ((Time2.QuadPart - Time1.QuadPart) > 500000) {
		return TRUE;
	}

	return FALSE;
}

BOOL DebugBreakCheck() {

	printf(
		"DebugBreak causes the breakpoint exception, EXCEPTION_BREAKPOINT, to occur in the current process. \n"
		"If the program is executed without a debugger, the control will be passed to the exception handler. \n"
		"Otherwise, the execution will be intercepted by the debugger, meaning it is being debugged. \n\n"
		"Is is supported by ScyllaHide?: %s \n",
		YES
	);

	__try {
		DebugBreak();
	}
	__except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
		// if the exception is equal to EXCEPTION_BREAKPOINT, EXCEPTION_EXECUTE_HANDLER is executed and the function return FALSE
		return FALSE;
	}

	// if the exception is not equal to EXCEPTION_BREAKPOINT, EXCEPTION_CONTINUE_SEARCH is executed and the function return TRUE
	return TRUE;
}

BOOL OutputDebugStringCheck() {

	printf(
		"WindAPI OutputDebugString can be used to send a string to the debugger for display. \n"
		"If a debugger exists, then OutputDebugString will succeed. \n\n"
		"Is is supported by ScyllaHide?: %s \n",
		YES
	);

	SetLastError(1);
	OutputDebugStringW(L"Calling OutputDebugString");

	// if GetLastError is 0, then OutputDebugStringW succeeded
	if (GetLastError() == 0) {
		return TRUE;
	}

	return FALSE;
}

int main() {

	// Obtain the PEB structure
#ifdef _WIN64
	PPEB	pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB	pPeb = (PEB*)(__readfsdword(0x30));
#endif

	int choice = NULL;
	char input[100];
	BOOL DEBUGGING = FALSE;

    BOOL (*functionPointers[10])() = {
		IsDebuggerPresentCheck, 
		IsDebuggerPresentCheck2,
		IsDebuggerPresentCheck3,
		NtQueryInfoProcCheck,
		HardwareBpCheck,
		BlackListCheck,
		GetTickCountCheck,
		QueryPerformanceCounterCheck,
		DebugBreakCheck,
		OutputDebugStringCheck
	};

	while (1){

		printf(
			"\n----------List of Anti-Debug checking techniques---------- \n"
			"1. IsDebuggerPresent \n"
			"2. IsDebuggerPresent Manually \n"
			"3. IsDebuggerPresent using NtGlobalFlag \n"
			"4. NtQueryInformationProcess \n"
			"5. Hardware BreakPoint Registers \n"
			"6. Debugger BlackList \n"
			"7. GetTickCount64 \n"
			"8. QueryPerformanceCounter \n"
			"9. DebugBreak \n"
			"10. OutputDebugString \n\n"
			"Enter a number for the check you want to debug. \n"
			"Or enter quit/exit to exit Program: "
		);

		if (fgets(input, sizeof(input), stdin) == NULL) {
			printf("Error reading input. Exiting the program.\n");
			exit(1);
		}

		// Remove the trailing newline character, if present
		input[strcspn(input, "\n")] = '\0';

		// Convert input string to lowercase for case-insensitive comparison
		for (int i = 0; input[i]; i++) {
			input[i] = tolower(input[i]);
		}

		if (strcmp(input, "exit") == 0 || strcmp(input, "quit") == 0) {
			// User entered 'exit' or 'quit' to exit the program
			break;
		}

		printf("\n\n");
		if (sscanf_s(input, "%d", &choice) == 1) {
			if (choice >= 1 && choice <= 10) {
				printf(
					"-------------------- Explanation --------------------\n"
				);
				if (choice == 2) {
					DEBUGGING = IsDebuggerPresentCheck2(pPeb);
				}
				else if (choice == 3) {
					DEBUGGING = IsDebuggerPresentCheck3(pPeb);
				}
				else {
					// Call selected function via function pointer
					DEBUGGING = functionPointers[choice - 1]();
				}
			}
			else {
				printf("Function Selection Failed. \n\n");
				continue;
			}
			if (DEBUGGING) {
				printf("Passed Debug Check: %s \n\n", NO);
			}
			else {
				printf("Passed Debug Check: %s \n\n", YES);
			}
		}
		else {
			printf("Function Selection Failed. \n\n");
			continue;
		}
	}

	return 0;
}
