
#include <iostream>
#include <Windows.h>
#include <vector>


// list of anti debug techniques found on https://anti-debug.checkpoint.com/

const std::vector<std::string> vWindowClasses = {
    "antidbg",
    "ID",               // Immunity Debugger
    "ntdll.dll",        // peculiar name for a window class
    "ObsidianGUI",
    "OLLYDBG",
    "Rock Debugger",
    "SunAwtFrame",
    "Qt5QWindowIcon"
    "WinDbgFrameClass", // WinDbg
    "Zeta Debugger",
    "Qt5QWindowIcon", // added this my self, its x64dbg window.
};

DWORD WINAPI IsDebugged([[maybe_unused]] LPVOID lpParameter)
{
    while (true) {
        for (auto& sWndClass : vWindowClasses)
        {
            // Check if the window exists
            if (NULL != FindWindowA(sWndClass.c_str(), NULL))
            {
                // Display a message box if a window is found
                MessageBoxA(NULL, "A debugging window was detected!", "Debugging Detected", MB_OK | MB_ICONWARNING);

            }
        }
    }
}


int main()
{
	MessageBoxA(nullptr, "Sample Application", "RE-KIT", MB_OK);
	GlobalFindAtomA("RE-KIT");
	if (IsDebuggerPresent()) {
		MessageBoxA(nullptr, "Debugger Found", "RE-KIT", MB_OK);
	}
	

	MessageBoxA(nullptr, "Sample Application", "RE-KIT", MB_OK);
}
