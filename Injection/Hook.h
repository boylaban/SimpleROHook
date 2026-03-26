// The following ifdef blocks are a common way to create macros that facilitate export from a DLL.
// All files in this DLL are compiled using the INJECTION_EXPORTS symbol defined on the command line.
// This symbol cannot be defined in projects that use this DLL.
// Other projects whose source file contains this file
// Consider the CORE_API function to be imported from a DLL,
// While this DLL considers the symbols defined in this macro to be exported.
#ifdef INJECTION_EXPORTS
	extern HINSTANCE g_hDLL;
	#define INJECTION_API extern "C" __declspec(dllexport)
#else
	#define INJECTION_API extern "C" __declspec(dllimport)
#endif

INJECTION_API void InstallHook();
INJECTION_API void RemoveHook();
