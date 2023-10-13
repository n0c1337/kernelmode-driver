#pragma once

#include "definitions.h"

bool KeReadPhysicalMemory(HANDLE pid, void* address, void* buffer, unsigned __int64 size);
bool KeWritePhysicalMemory(HANDLE pid, void* address, void* buffer, unsigned __int64 size);
bool KeReadVirtualMemory(HANDLE pid, unsigned __int64 address, void* buffer, unsigned __int64 size);
bool KeWriteVirtualMemory(HANDLE pid, unsigned __int64 address, void* buffer, unsigned __int64 size);
unsigned long long KeGetModuleBase(PEPROCESS process, UNICODE_STRING module_name);
