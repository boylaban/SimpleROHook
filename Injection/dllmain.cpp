// dllmain.cpp: Defines the entry point for the DLL application.
#include "Hook.h"

#include "tinyconsole.h"

#include "ProxyIDirectDraw.h"
#include "ProxyIDirectInput.h"

#include "Core/RoCodeBind.h"

#include "versioninfo.h"

static BOOL g_useMinHook = TRUE;

BOOL InstallProxyFunction(LPCTSTR dllname, LPCSTR exportname, VOID *ProxyFunction, LPVOID *pOriginalFunction)
{
	DEBUG_LOGGING_NORMAL(("InstallProxyFunction(%s:%s)", dllname, exportname));
	BOOL result = FALSE;

	if (g_useMinHook)
	{
		LPVOID ppTarget;
		LPWSTR dllnameW;

#ifdef UNICODE
		// This is kinda silly since none of the other code cares about supporting DUNICODE but hey
		dllnameW = dllname;
#else
		int len = MultiByteToWideChar(CP_ACP, 0, dllname, -1, NULL, 0);

		if (len == 0)
		{
			DEBUG_LOGGING_NORMAL(("dllname conversion length check failed (WTF?)"));
			goto fallback;
		}

		dllnameW = new wchar_t[len];

		if (MultiByteToWideChar(CP_ACP, 0, dllname, -1, dllnameW, len) == 0)
		{
			DEBUG_LOGGING_NORMAL(("dllname conversion failed (WTF?)"));
			goto error_free_wstr;
		}
#endif

		int result = MH_CreateHookApiEx(dllnameW, exportname, ProxyFunction, pOriginalFunction, &ppTarget);

		if (result != MH_OK)
		{
			DEBUG_LOGGING_NORMAL(("MH_CreateHookApiEx() failed (%d)", result));
			goto error_free_wstr;
		}

		result = MH_EnableHook(ppTarget);

		if (result != MH_OK)
		{
			DEBUG_LOGGING_NORMAL(("MH_EnableHook failed (%d)", result));
			goto error_free_wstr;
		}
		else
		{
			DEBUG_LOGGING_NORMAL(("success"));
			return TRUE;
		}

	error_free_wstr:
#ifdef UNICODE
		delete[] dllnameW;
#endif
		;
	}

fallback:
	// Fall back to old code, probably don't need this but it's there
	DEBUG_LOGGING_NORMAL(("Trying fallback"));
	std::stringstream fullpath;

	TCHAR systemdir[MAX_PATH];
	HMODULE hDll;
	::GetSystemDirectory(systemdir, MAX_PATH);

	fullpath << systemdir << "\\" << dllname;
	hDll = ::LoadLibrary(fullpath.str().c_str());

	if (!hDll)
		return result;

	BYTE *p = (BYTE*)::GetProcAddress(hDll, exportname);
	DEBUG_LOGGING_DETAIL(("%08X :%s(%08X)\n", hDll, exportname, p));

	if (p)
	{
		if (p[ 0] == 0x8b && p[ 1] == 0xff &&
		  ((p[-5] == 0x90 && p[-4] == 0x90 && p[-3] == 0x90 && p[-2] == 0x90 && p[-1] == 0x90) ||
		   (p[-5] == 0xcc && p[-4] == 0xcc && p[-3] == 0xcc && p[-2] == 0xcc && p[-1] == 0xcc))
			)
		{
			// Find hotpatch structure.
			//
			// 9090909090    ///< 005 | nop     x 5
			// 8BFF          ///< 007 | mov     edi, edi
			//       or
			// CCCCCCCCCC    ///< 005 | int     3 x 5
			// 8BFF          ///< 007 | mov     edi, edi
			DWORD flOldProtect, flDontCare;

			if (::VirtualProtect((LPVOID)&p[-5], 7, PAGE_READWRITE, &flOldProtect))
			{
				p[-5] = 0xe9;                 // jmp
				p[ 0] = 0xeb; p[1] = 0xf9;    // jmp     short [pc-7]

				DEBUG_LOGGING_DETAIL(("hook type a\n"));
				*pOriginalFunction = (void*)&p[2];
				*((DWORD*)&p[-4]) = (DWORD)ProxyFunction - (DWORD)&p[-5] - 5;

				::VirtualProtect((LPVOID)&p[-5], 7, flOldProtect, &flDontCare);
				result = TRUE;
			}
		}
		else if (p[-5] == 0xe9 &&
				 p[ 0] == 0xeb &&
				 p[ 1] == 0xf9
				)
		{
			// Find hotpached function.
			//
			// jmp     ****
			// jmp     short [pc-7]
			DWORD flOldProtect, flDontCare;

			if (::VirtualProtect((LPVOID)&p[-5], 7, PAGE_READWRITE, &flOldProtect))
			{
				DEBUG_LOGGING_DETAIL(("hook type b\n"));
				*pOriginalFunction = (LPVOID)(*((DWORD*)&p[-4]) + (DWORD)&p[-5] + 5);
				*((DWORD*)&p[-4]) = (DWORD)ProxyFunction - (DWORD)&p[-5] - 5;

				::VirtualProtect((LPVOID)&p[-5], 7, flOldProtect, &flDontCare);
				result = TRUE;
			}
		}
		else if (p[ 0] == 0xe9 &&
			   ((p[-5] == 0x90 && p[-4] == 0x90 && p[-3] == 0x90 && p[-2] == 0x90 && p[-1] == 0x90) ||
				(p[-5] == 0xcc && p[-4] == 0xcc && p[-3] == 0xcc && p[-2] == 0xcc && p[-1] == 0xcc))
				)
		{
			// Find irregular hook code. (Case by iRO)
			//
			// 9090909090    ///< 005 | nop     x 5
			// E9********    ///< 010 | jmp     im4byte
			//       or
			// CCCCCCCCCC    ///< 005 | int     3 x 5
			// E9********    ///< 010 | jmp     im4byte
			DWORD flOldProtect, flDontCare;

			if (::VirtualProtect((LPVOID)&p[0], 5, PAGE_READWRITE, &flOldProtect))
			{
				DEBUG_LOGGING_DETAIL(("hook type c\n"));
				*pOriginalFunction = (LPVOID)(*((DWORD*)&p[1]) + (DWORD)&p[0] + 5);
				*((DWORD*)&p[1]) = (DWORD)ProxyFunction - (DWORD)&p[0] - 5;

				::VirtualProtect((LPVOID)&p[0], 5, flOldProtect, &flDontCare);
				result = TRUE;
			}
		}
	}

	::FreeLibrary(hDll);

	return result;
}

void *pResumeAIL_open_digital_driverFunction;
void __declspec(naked) ProxyAIL_open_digital_driver(void)
{
	__asm mov     eax, [esp+0x04]    // eax = soundrate
	__asm add     [esp+0x04], eax    // soundrate + soundrate (soundrate x 2)
	__asm sub     esp, 0x010
	__asm jmp     pResumeAIL_open_digital_driverFunction
}

BOOL RagexeSoundRateFixer(void)
{
	BOOL result = FALSE;
	std::stringstream fullpath;

	TCHAR currentdir[MAX_PATH];
	HINSTANCE hDll;
	::GetCurrentDirectoryA(MAX_PATH, currentdir);

	fullpath << currentdir << "\\Mss32.dll";
	hDll = ::LoadLibrary(fullpath.str().c_str());

	if (!hDll)
		return result;

	BYTE *p = (BYTE*)::GetProcAddress(hDll, "_AIL_open_digital_driver@16");

	if (p)
	{
		if (p[0] == 0x83 && p[1] == 0xec && p[2] == 0x10)
		{
			// Find hotpatch structure.
			DWORD flOldProtect, flDontCare;

			if (::VirtualProtect((LPVOID)&p[-5], 7, PAGE_READWRITE, &flOldProtect))
			{
				p[-5] = 0xe9;                 // jmp
				p[ 0] = 0xeb; p[1] = 0xf9;    // jmp     short [pc-7]
				p[ 2] = 0x90;                 // nop

				pResumeAIL_open_digital_driverFunction = &p[3];
				*((DWORD*)&p[-4]) = (DWORD)ProxyAIL_open_digital_driver - (DWORD)&p[-5] -5;

				::VirtualProtect((LPVOID)&p[-5], 7, flOldProtect, &flDontCare);
				result = TRUE;
			}
		}
	}

	::FreeLibrary(hDll);

	return result;
}

typedef HRESULT (WINAPI *tDirectDrawCreateEx)(GUID FAR *lpGUID, LPVOID *lplpDD, REFIID iid, IUnknown FAR *pUnkOuter);
typedef HRESULT (WINAPI *tDirectInputCreateA)(HINSTANCE hinst, DWORD dwVersion, LPDIRECTINPUTA *ppDI, LPUNKNOWN punkOuter);
typedef HRESULT (WINAPI *tDirectInput8Create)(HINSTANCE hinst, DWORD dwVersion, REFIID riidltf, LPVOID *ppvOut, LPUNKNOWN punkOuter);

typedef int (WSAAPI *tWS2_32_recv)(SOCKET s, char *buf, int len, int flags);

tDirectDrawCreateEx OrigDirectDrawCreateEx = NULL;
tDirectInputCreateA OrigDirectInputCreateA = NULL;
tDirectInput8Create OrigDirectInput8Create = NULL;

HMODULE g_ws2_32_dll = NULL;
tWS2_32_recv OrigWS2_32_recv = NULL;

int WSAAPI ProxyWS2_32_recv(SOCKET s, char *buf, int len, int flags)
{
	int result;

	result = OrigWS2_32_recv(s, buf, len, flags);

	if (g_pRoCodeBind)
		g_pRoCodeBind->PacketQueueProc(buf, result);

	return result;
}

HRESULT WINAPI ProxyDirectDrawCreateEx(GUID FAR *lpGuid, LPVOID *lplpDD, REFIID iid, IUnknown FAR *pUnkOuter)
{
	DEBUG_LOGGING_MORE_DETAIL(("DirectDrawCreateEx hookfunc\n"));
	HRESULT Result = OrigDirectDrawCreateEx(lpGuid, lplpDD, iid, pUnkOuter);

	if (FAILED(Result))
		return Result;

	CProxyIDirectDraw7 *lpcDD;
	*lplpDD = lpcDD = new CProxyIDirectDraw7((IDirectDraw7*)*lplpDD);
	lpcDD->setThis(lpcDD);
	DEBUG_LOGGING_MORE_DETAIL(("DirectDrawCreateEx Hook hookfunc"));

	return Result;
}

HRESULT WINAPI ProxyDirectInputCreateA(HINSTANCE hinst, DWORD dwVersion, LPDIRECTINPUTA *ppDI, LPUNKNOWN punkOuter)
{
	DEBUG_LOGGING_NORMAL(("DirectInputCreateA hookfunc instance = %08X", hinst));
	HRESULT Result = OrigDirectInputCreateA(hinst, dwVersion, ppDI, punkOuter);

	if (FAILED(Result))
		return Result;

	if (dwVersion == 0x0700)
		*ppDI = new CProxyIDirectInput7((IDirectInput7*)*ppDI);

	DEBUG_LOGGING_NORMAL(("DirectInputCreateA Hook success"));

	return Result;
}

HRESULT WINAPI ProxyDirectInput8Create(HINSTANCE hinst, DWORD dwVersion, REFIID riidltf, LPVOID *ppvOut, LPUNKNOWN punkOuter)
{
	DEBUG_LOGGING_NORMAL(("DirectInput8Create hookfunc instance = %08X", hinst));
	HRESULT Result = OrigDirectInput8Create(hinst, dwVersion, riidltf, ppvOut, punkOuter);

	if (FAILED(Result))
		return Result;

	// We don't have a DInput8 proxy yet, but this at least confirms the hook is working
	DEBUG_LOGGING_NORMAL(("DirectInput8Create Hook success (Interface: %08X)", riidltf.Data1));

	return Result;
}

BOOL IsRagnarokApp(void)
{
	TCHAR path[MAX_PATH];
	TCHAR checkPath[MAX_PATH];

	TCHAR fullPath[MAX_PATH];

	// Get the directory containing the current executable
	if (::GetModuleFileName(NULL, fullPath, MAX_PATH) == 0)
		return FALSE;

	// Copy full path to path and then remove file spec to get directory
	_tcscpy_s(path, MAX_PATH, fullPath);
	::PathRemoveFileSpec(path);

	// Exclusion: Do NOT initialize in common RO setup/patching tools 
	// (These coexist in the game folder but aren't the game itself)
	TCHAR* exeName = ::PathFindFileName(fullPath); 

	TCHAR* lowExe = _tcsdup(exeName);
	_tcslwr_s(lowExe, _tcslen(lowExe) + 1);

	bool isExcluded = (_tcsstr(lowExe, _T("setup")) != NULL) || 
	                  (_tcsstr(lowExe, _T("patcher")) != NULL) || 
	                  (_tcsstr(lowExe, _T("thor")) != NULL) || 
	                  (_tcsstr(lowExe, _T("cleaner")) != NULL) || 
	                  (_tcsstr(lowExe, _T("editor")) != NULL) ||
	                  (_tcsstr(lowExe, _T("simplerohook")) != NULL) ||
	                  (_tcsstr(lowExe, _T("injector")) != NULL);

	free(lowExe);

	if (isExcluded)
		return FALSE;

	// 1. Check for data.grf (Main RO archive)
	_stprintf_s(checkPath, _T("%s\\data.grf"), path);
	if (::GetFileAttributes(checkPath) != INVALID_FILE_ATTRIBUTES)
		return TRUE;

	// 2. Check for data directory (Loose files mode)
	_stprintf_s(checkPath, _T("%s\\data"), path);
	DWORD attr = ::GetFileAttributes(checkPath);
	if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
		return TRUE;

	// 3. Check for sclientinfo.xml (Common client config)
	_stprintf_s(checkPath, _T("%s\\sclientinfo.xml"), path);
	if (::GetFileAttributes(checkPath) != INVALID_FILE_ATTRIBUTES)
		return TRUE;

	return FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;

		case DLL_PROCESS_ATTACH:
			g_hDLL = hModule;

			if (IsRagnarokApp())
			{
				TCHAR temppath[MAX_PATH];
				::DisableThreadLibraryCalls(hModule);

				CreateTinyConsole();

				if (MH_Initialize() != MH_OK)
				{
					DEBUG_LOGGING_NORMAL(("MH_Initialize() failed, falling back to old DLL proxy code"));
				}

				DEBUG_LOGGING_NORMAL(("Version: %s (Built at: %s %s)", GIT_VERSION, __DATE__, __TIME__));
				OpenSharedMemory();

#ifdef USE_WS2_32DLLINJECTION
				InstallProxyFunction(_T("ws2_32.dll"), "recv", ProxyWS2_32_recv, (LPVOID*)&OrigWS2_32_recv);
#endif

				if (g_pSharedData)
				{
					::GetCurrentDirectory(MAX_PATH, temppath);
					strcat_s(temppath, "\\BGM\\");

					::MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, temppath, strlen(temppath) + 1, g_pSharedData->musicfilename, MAX_PATH);
					g_FreeMouseSw = g_pSharedData->freemouse;

					if (g_pSharedData->_44khz_audiomode)
						RagexeSoundRateFixer();

					if (g_pSharedData->chainload)
					{
						char currentdir[MAX_PATH];
						::GetCurrentDirectoryA(MAX_PATH, currentdir);

						// LoadLibrary fails gracefully, so we just try to load both files
						// if one doesn't exist, ignore it
						if (!GetModuleHandle("dinput.dll"))
						{
							std::stringstream dinput_dll_path;
							dinput_dll_path << currentdir << "\\dinput.dll";
							::LoadLibraryA(dinput_dll_path.str().c_str());
						}

						std::stringstream dinput_asi_path;
						dinput_asi_path << currentdir << "\\dinput.asi";
						::LoadLibraryA(dinput_asi_path.str().c_str());
					}
				}

				InstallProxyFunction(_T("ddraw.dll")  , "DirectDrawCreateEx", ProxyDirectDrawCreateEx, (LPVOID*)&OrigDirectDrawCreateEx);
				InstallProxyFunction(_T("dinput.dll") , "DirectInputCreateA", ProxyDirectInputCreateA, (LPVOID*)&OrigDirectInputCreateA);
				InstallProxyFunction(_T("dinput8.dll"), "DirectInput8Create" , ProxyDirectInput8Create, (LPVOID*)&OrigDirectInput8Create);
			}
			break;

		case DLL_PROCESS_DETACH:
			if (IsRagnarokApp())
			{
				ReleaseTinyConsole();
				ReleaseSharedMemory();
			}
			break;
	}

	return TRUE;
}
