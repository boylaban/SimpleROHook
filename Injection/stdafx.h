// stdafx.h: Include file for standard system include files, or
// write a project-specific include file that is referenced frequently
// and does not change much.
//

#pragma once

#include "TargetVer.h"

#define WIN32_LEAN_AND_MEAN  // Exclude unused parts from the Windows header.

// Windows Header Files:
#include <Windows.h>
#include <WinSock2.h>
#include <Shlwapi.h>
#include <mmsystem.h>
#include <RichEdit.h>
#include <tchar.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ddraw.lib")
#pragma comment(lib, "dinput8.lib")
#pragma comment(lib, "dxguid.lib")
#pragma comment(lib, "winmm.lib")

#define DIRECTINPUT_VERSION 0x0700
#include <ddraw.h>
#include <d3d.h>
#include <dinput.h>

// TODO: See here for any additional headers required by your program.
#include <process.h>

#include <math.h>

#include <vector>
#include <array>
#include <list>
#include <map>

#include <iostream>
#include <iomanip>

#include <string>
#include <sstream>
#include <fstream>

#include <cwchar>

#include "MinHook.h"
