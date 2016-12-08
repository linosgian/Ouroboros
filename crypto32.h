#pragma once

#include <winsock2.h>
#include <d3d9.h>
#include <stddef.h>
#include <iostream>
#include <WS2tcpip.h>
#include <tlhelp32.h>
#include <io.h>
#include <comdef.h> 

#define DEBUG 0

#define MAX_THREADS 3
#define BUF_SIZE 255
#define MAX_COMP_NAME 50
#define USERNAME_BUF 120
#define CPU_STR_SIZE 0x40
#define HOST_STR_SIZE 200
#define SHA256_DIGEST_LENGTH 65

#if DEBUG
#define DEBUG_CODE(x){x}
#else
#define DEBUG_CODE(x)
#endif


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "crypt32.lib")