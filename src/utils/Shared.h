#pragma once
#include <windows.h>
#include <string>

namespace utils {
    DWORD djb2Hash(const std::string& str);
    FARPROC getProcByHash(HMODULE hModule, DWORD hash);
}
