#include "memory.h"

bool KeReadPhysicalMemory(HANDLE pid, void* address, void* buffer, unsigned __int64 size)
{
	if (!pid || !address || !buffer || !size)
		return false;

	PEPROCESS process = 0;
	PsLookupProcessByProcessId(pid, &process);
	if (!process)
		return false;

	KAPC_STATE state;
	KeStackAttachProcess(process, &state);

	MM_COPY_ADDRESS physical_address = { 0 };

	physical_address.PhysicalAddress = MmGetPhysicalAddress(address);
	KeUnstackDetachProcess(&state);

	SIZE_T bytes = 0;

	NTSTATUS status = MmCopyMemory(buffer, physical_address, size, MM_COPY_MEMORY_PHYSICAL, &bytes);

	if (!NT_SUCCESS(status))
		return false;
	else
		return true;
}

bool KeWritePhysicalMemory(HANDLE pid, void* address, void* buffer, unsigned __int64 size)
{
	if (!pid || !address || !buffer || !size)
		return false;

	PEPROCESS process = 0;
	PsLookupProcessByProcessId(pid, &process);
	if (!process)
		return false;
	
	KAPC_STATE state;
	KeStackAttachProcess(process, &state);

	PHYSICAL_ADDRESS physical_address = MmGetPhysicalAddress(address);
	
	KeUnstackDetachProcess(&state);
	void* mappedMemory = MmMapIoSpaceEx(physical_address, size, PAGE_READWRITE);
	if (!mappedMemory) return false;

	memcpy(mappedMemory, buffer, size);
	MmUnmapIoSpace(mappedMemory, size);
	return true;
	
}

bool KeReadVirtualMemory(HANDLE pid, unsigned __int64 address, void* buffer, unsigned __int64 size)
{
	if (!pid || !address || !buffer || !size)
		return false;

	SIZE_T Result = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	PsLookupProcessByProcessId((HANDLE)pid, &process);

	status = MmCopyVirtualMemory(process, (void*)address, (PEPROCESS)PsGetCurrentProcess(), (void*)buffer, size, KernelMode, &Result);

	if (!NT_SUCCESS(status))
		return false;
	else
		return true;
}

bool KeWriteVirtualMemory(HANDLE pid, unsigned __int64 address, void* buffer, unsigned __int64 size)
{
	if (!pid || !address || !buffer || !size)
		return false;

	SIZE_T Result = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	PsLookupProcessByProcessId((HANDLE)pid, &process);

	status = MmCopyVirtualMemory(PsGetCurrentProcess(), (void*)address, process, (void*)buffer, size, KernelMode, &Result);

	if (!NT_SUCCESS(status))
		return false;
	else
		return true;

}

unsigned __int64 KeGetModuleBase(PEPROCESS process, UNICODE_STRING module_name)
{
	PPEB pPeb = PsGetProcessPeb(process);

	if (!pPeb)
	{
		return NULL;
	}

	KAPC_STATE state;

	KeStackAttachProcess(process, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	if (!pLdr)
	{
		KeUnstackDetachProcess(&state);
		return NULL;
	}

	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink; list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == NULL)
		{
			ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}
	}

	KeUnstackDetachProcess(&state);
	return NULL;
}
