
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

DWORD WINAPI print_test([[maybe_unused]] LPVOID lpParameter) {
    while (true) {
		printf("Test message\n");
    }
}

int main()
{
	MessageBoxA(nullptr, "Sample Application", "RE-KIT", MB_OK);
	// Create a new thread to check for debugging windows
	CreateThread(NULL, 0, print_test, NULL, 0, NULL);

    MessageBoxA(nullptr, "Sample Application", "RE-KIT", MB_OK);
}
