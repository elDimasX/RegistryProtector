

#include <fltKernel.h>

// Quanto mais alto for a altitude, mais rapidamente seu driver será chamado
// Quando ocorrer uma operação no registro
UNICODE_STRING AltitudeReg = RTL_CONSTANT_STRING(L"380002");
LARGE_INTEGER Cookie = { 0 };


#define TAG 'pRE'

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

VOID Unload(
	_In_ PDRIVER_OBJECT DriverObject
);

NTSTATUS RegistrerRegistryCallback(
	_In_ PVOID Context,
	_In_ PVOID Argument1,
	_In_ PVOID Argument2
);

BOOLEAN GetRegistryObjectCompleteName(
	_In_ PUNICODE_STRING Path,
	_In_ PVOID RegistryObject
);

BOOLEAN GrantProcess(
	_In_ PEPROCESS CurrentProcess
);

PUNICODE_STRING GetFullProcessName(
	_In_ PEPROCESS Process
);

NTSTATUS
PsReferenceProcessFilePointer(
	_In_ PEPROCESS Process,
	_In_ PVOID* OutFileObject 
);
