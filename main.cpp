#include "hook.h"
#include "utils.h"

// Quadword(QWORD for short) Signature of NtUserSetInteractiveCtrlRotationAngle, easily obtained via IDA and SigMaker
#define NT_QWORD_SIG "\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x10\x44\x8B\x54\x24\x00\x44\x89\x54\x24\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x38\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x38\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x06\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x38\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x06\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x38" 
#define NT_QWORD_MASK "xxx????xxxxxxxxx?xxxx?xx????xxxxxxxxxxxxxxxxxxx????xxxxxxx????xxxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxxxxxxxxxxxxxxxxx"
// win32k + 0x66648 (prolly already changed)

extern "C" NTSTATUS DriverEntry()
{
	const unsigned __int64 win32k = KeGetKernelModule("win32k.sys");

	
	unsigned __int64 nt_qword{};

	if (win32k) {
		nt_qword = KeScanPattern(win32k, NT_QWORD_SIG, NT_QWORD_MASK);
	}
	else {
		return STATUS_UNSUCCESSFUL;
	}

	// +3 ) + 7 because we don't want the first byte of the signature
	const unsigned __int64 nt_qword_derefernce = (unsigned __int64)nt_qword + *(int*)((BYTE*)nt_qword + 3) + 7;
	*(void**)&oNtUserSetInteractiveCtrlRotationAngle = InterlockedExchangePointer((void**)nt_qword_derefernce, (void*)hkFunction);
	
	printk("Hooked!");

	return STATUS_SUCCESS;
}