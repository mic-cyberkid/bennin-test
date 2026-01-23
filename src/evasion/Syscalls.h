#pragma once
#include <windows.h>
#include <map>
#include <string>
#include <vector>

namespace evasion {

struct SyscallStub {
    DWORD ssn;
    PVOID address;
};

class SyscallResolver {
public:
    static SyscallResolver& GetInstance();

    // Resolves a syscall by name (e.g., "NtAllocateVirtualMemory")
    DWORD GetServiceNumber(const std::string& functionName);
    
    // Gets the address of the 'syscall; ret' gadget in ntdll
    PVOID GetSyscallGadget();

private:
    SyscallResolver();
    void ResolveAll();
    
    std::map<std::string, DWORD> m_syscallMap;
    PVOID m_syscallGadget = nullptr;
};

} // namespace evasion

// Helper for calling syscalls (requires assembly or gadget jump)
extern "C" NTSTATUS InternalDoSyscall(DWORD ssn, ...);

// Structures for syscalls
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);          \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}

// Syscall prototypes
extern "C" NTSTATUS NtCreateKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG TitleIndex,
    IN PUNICODE_STRING Class,
    IN ULONG CreateOptions,
    OUT PULONG Disposition
);

extern "C" NTSTATUS NtSetValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN ULONG TitleIndex,
    IN ULONG Type,
    IN PVOID Data,
    IN ULONG DataSize
);

extern "C" NTSTATUS NtClose(
    IN HANDLE Handle
);
