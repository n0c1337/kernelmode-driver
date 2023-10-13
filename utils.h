#pragma once

#include "definitions.h"

void* KeGetSystemInformation(SYSTEM_INFORMATION_CLASS information_class)
{
    unsigned long size = 32;
    char buffer[32];

    ZwQuerySystemInformation(information_class, buffer, size, &size);

    void* info = ExAllocatePoolZero(NonPagedPool, size, 'kloa'); // Pooltag doesn't matter that much in this case
    if (!info)
        return nullptr;

    if (!NT_SUCCESS(ZwQuerySystemInformation(information_class, info, size, &size))) {
        ExFreePool(info);
        return nullptr;
    }

    return info;
}

unsigned __int64 KeGetKernelModule(const char* name)
{
    const auto to_lower_case = [](char* string) -> const char* {
        for (char* pointer = string; *pointer != '\0'; ++pointer) {
            *pointer = (char)(short)tolower(*pointer);
        }

        return string;
    };

    const PRTL_PROCESS_MODULES info = (PRTL_PROCESS_MODULES)KeGetSystemInformation(SystemModuleInformation);

    if (!info)
        return NULL;

    for (size_t i = 0; i < info->NumberOfModules; ++i) {
        const RTL_PROCESS_MODULE_INFORMATION& module = info->Modules[i];

        if (strcmp(to_lower_case((char*)module.FullPathName + module.OffsetToFileName), name) == 0) {
            const void* address = module.ImageBase;
            ExFreePool(info);
            return (unsigned __int64)address;
        }
    }

    ExFreePool(info);
    return NULL;
}

unsigned __int64 KeScanPattern(unsigned __int64 base, size_t range, const char* pattern, const char* mask)
{
    const auto check_mask = [](const char* base, const char* pattern, const char* mask) -> bool {
        for (; *mask; ++base, ++pattern, ++mask) {
            if (*mask == 'x' && *base != *pattern)
                return false;
        }

        return true;
    };

    range = range - strlen(mask);

    for (size_t i = 0; i < range; ++i) {
        if (check_mask((const char*)base + i, pattern, mask))
            return base + i;
    }

    return NULL;
}

// Only works because Kernel Drivers are all running in the same virtual address space.
unsigned __int64 KeScanPattern(unsigned __int64 base, const char* pattern, const char* mask)
{
    const PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    const PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

    for (size_t i = 0; i < headers->FileHeader.NumberOfSections; i++) {
        const PIMAGE_SECTION_HEADER section = &sections[i];

        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) // Only executable sections
        {
            const unsigned __int64 match = KeScanPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
            if (match)
                return match;
        }
    }

    return 0;
}