#pragma once

#include "memory.h"

__int64(__fastcall* oNtUserSetInteractiveCtrlRotationAngle)(void* a1);
__int64 __fastcall hkFunction(void* a1)
{
	if (reinterpret_cast<cmd_t*>(a1)->verification_code != CALL_CODE)
		return oNtUserSetInteractiveCtrlRotationAngle(a1);

	cmd_t* cmd = reinterpret_cast<cmd_t*>(a1);

	switch (cmd->operation)
	{
	case read_vm: {
		if (cmd->address < 0x7FFFFFFFFFFF && cmd->address > 0)
		{
			KeReadVirtualMemory((HANDLE)cmd->pid, cmd->address, cmd->buffer, cmd->size);
		}
		cmd->success = true;
		break;
	}
	case write_vm: {
		if (cmd->address < 0x7FFFFFFFFFFF && cmd->address > 0)
		{
			PVOID kernelBuff = ExAllocatePool(NonPagedPool, cmd->size);
			if (!kernelBuff)
			{
				return STATUS_UNSUCCESSFUL;
			}

			if (!memcpy(kernelBuff, cmd->buffer, cmd->size))
			{
				return STATUS_UNSUCCESSFUL;
			}
			KeWriteVirtualMemory((HANDLE)cmd->pid, cmd->address, kernelBuff, cmd->size);
			ExFreePool(kernelBuff);
		}
		cmd->success = true;
		break;
	}
	case read_phy: {
		KeReadPhysicalMemory((HANDLE)cmd->pid, (void*)cmd->address, cmd->buffer, cmd->size);
		cmd->success = true;
		break;
	}
	case write_phy: {
		KeWritePhysicalMemory((HANDLE)cmd->pid, (void*)cmd->address, cmd->buffer, cmd->size);
		cmd->success = true;
		break;
	}
	case get_module: {
		ANSI_STRING AS;
		UNICODE_STRING ModuleName;

		RtlInitAnsiString(&AS, cmd->module_name);
		RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);

		PEPROCESS process;
		PsLookupProcessByProcessId((HANDLE)cmd->pid, &process);
		ULONG64 base_address64 = NULL;
		base_address64 = KeGetModuleBase(process, ModuleName);
		if (base_address64 != NULL) {
			cmd->base_address = base_address64;
		}
		RtlFreeUnicodeString(&ModuleName);
		cmd->success = true;
		break;
	}
	default: {
		cmd->success = false;
		break;
	}
	}

	return 0;
}