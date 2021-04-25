///
/// Protetor de registro em kernel mode
/// Use para proteger valores especificos
/// Funciona para anti-cheat ou antiv�rus, at� malware
///


#include "header.h"

BOOLEAN GetRegistryObjectCompleteName(
	_In_ PUNICODE_STRING Path,
	_In_ PVOID RegistryObject
)
{
	BOOLEAN Name = FALSE;
	BOOLEAN Partial = FALSE;

	// Se n�o for um endere�o v�lido
	if (!MmIsAddressValid(RegistryObject) || RegistryObject == NULL)
	{
		return FALSE;
	}

	__try
	{
		NTSTATUS Status;
		ULONG returnLength;
		PUNICODE_STRING ObjectName = NULL;

		Status = ObQueryNameString(
			RegistryObject,
			(POBJECT_NAME_INFORMATION)ObjectName,
			0,
			&returnLength
		);

		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			ObjectName = ExAllocatePoolWithTag(NonPagedPool, returnLength, TAG);

			Status = ObQueryNameString(RegistryObject, (POBJECT_NAME_INFORMATION)ObjectName, returnLength, &returnLength);

			if (NT_SUCCESS(Status))
			{
				// N�s salvamos o nome do registro em ObjectName, agora passe para a v�riavel
				// Path, para que a fun��o que n�s chamou obtenha o nome do arquivo completo
				RtlCopyUnicodeString(Path, ObjectName);

				// Sucesso
				Name = TRUE;
			}
		}

		if (ObjectName != NULL)
		{
			ExFreePoolWithTag(ObjectName, TAG);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("An error as ocurred"));
	}

	return Name;
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	/*
	
		Avisa que queremos obter opera��es que acontecem no registro
		Mais explica��es no link a seguir:
		https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex

	*/
	NTSTATUS Status = CmRegisterCallbackEx(
		RegistrerRegistryCallback,
		&AltitudeReg,
		DriverObject,
		NULL,
		&Cookie,
		NULL
	);

	if (!NT_SUCCESS(Status))
	{
		KdPrint(("Fail to registrer callback: %x", Status));
	}

	KdPrint(("Success to registrer callback: %x", Status));
	DriverObject->DriverUnload = Unload;
	return Status;
}

NTSTATUS RegistrerRegistryCallback(
	_In_ PVOID Context,
	_In_ PVOID Argument1,
	_In_ PVOID Argument2
)
{
	UNREFERENCED_PARAMETER(Context);
	REG_NOTIFY_CLASS Class = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

	if (

		// Se for algumas destas opera��es
		RegNtPreDeleteKey == Class ||
		RegNtPreDeleteValueKey == Class ||
		RegNtPreSetValueKey == Class ||
		RegNtPreCreateKey == Class ||
		RegNtPreRenameKey == Class
	)
	{
		// Local que est� sendo modificado, vamos guarda-l� aqui
		UNICODE_STRING Path;
		Path.Length = 0;

		// M�ximo de aloca��o no UNICODE
		Path.MaximumLength = 1024 * sizeof(WCHAR);

		// Aloque um espa�o na mem�ria
		Path.Buffer = ExAllocatePoolWithTag(NonPagedPool, Path.MaximumLength, TAG);

		if (Path.Buffer != NULL)
		{
			if (GetRegistryObjectCompleteName
			(
				&Path,
				((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Object
			) == FALSE)
			{
				ExFreePoolWithTag(Path.Buffer, TAG);
				KdPrint(("Fail to get registry name"));
				return STATUS_SUCCESS;
			}

			// Obtenha o processo que est� tentando modificar os valores
			PEPROCESS Process = PsGetCurrentProcess();

			if (wcsstr(Path.Buffer, L"Nottext File Remove") != NULL && GrantProcess(Process) == FALSE)
			{
				ExFreePoolWithTag(Path.Buffer, TAG);
				return STATUS_ACCESS_DENIED;
			}
		}
	}

	return STATUS_SUCCESS;
}

PUNICODE_STRING GetFullProcessName(
	_In_ PEPROCESS Process
)
{
	__try {

		PFILE_OBJECT FileObject = NULL;
		POBJECT_NAME_INFORMATION FileObjectInfo = NULL;

		NTSTATUS Status;
		Status = PsReferenceProcessFilePointer(Process, &FileObject);
		
		if (!NT_SUCCESS(Status))
		{
			return NULL;
		}

		Status = IoQueryFileDosDeviceName(FileObject, &FileObjectInfo);
		if (!NT_SUCCESS(Status))
		{
			return NULL;
		}

		ObDereferenceObject(FileObject);
		
		// Retorne o nome do arquivo em UNICODE_STRING
		return &(FileObjectInfo->Name);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	return NULL;
}

BOOLEAN GrantProcess(
	_In_ PEPROCESS CurrentProcess
)
{
	ANSI_STRING ProcessName;
	BOOLEAN ProcessAllowed = FALSE;

	__try {
		NTSTATUS Status;

		Status = RtlUnicodeStringToAnsiString(
			&ProcessName,
			(UNICODE_STRING*)GetFullProcessName(CurrentProcess),
			TRUE
		);

		if (!NT_SUCCESS(Status))
		{
			return ProcessAllowed;
		}

		// Coloque o locais do arquivos aqui, eles poder�o modificar os registros
		// Protegidos
		if (strstr(_strupr(ProcessName.Buffer), "C:\\WINDOWS\\EXPLORER.EXE"))
		{
			ProcessAllowed = TRUE;
		}
		else {
			KdPrint(("Process denied: %s", ProcessName.Buffer));
		}

		RtlFreeAnsiString(&ProcessName);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("Failed to get process name"));
	}

	return ProcessAllowed;
}

VOID Unload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	CmUnRegisterCallback(Cookie);
}
