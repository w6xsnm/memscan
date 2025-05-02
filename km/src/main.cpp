#include <ntifs.h>

//undocumented windows internal functions (exported by ntoskrnl)
extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName,
										PDRIVER_INITIALIZE InitializaionFunction);
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
											 PEPROCESS TargetProcess, PVOID TargetAddress,
											 SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
											 PSIZE_T ReturnSize);
}

/**
 * @brief Print debug message from km
 * @param text Debug message
 */
void DebugPrint(PCSTR text) {
#ifndef DEBUG
	UNREFERENCED_PARAMETER(text);
#endif

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
}

namespace driver {
	namespace codes {
		// Setup the driver
		constexpr ULONG attach = 
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		// Read process memory
		constexpr ULONG read =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		
		// Write process memory
		constexpr ULONG write =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	} //namespace codes

	// Shared between um & km
	struct Request {
		HANDLE ProcessId;

		PVOID pTarget;
		PVOID pBuffer;

		SIZE_T BufferSize;
		SIZE_T ReturnSize;
	};

	//IRP major functions

	/*NTSTATUS unsupported(PDEVICE_OBJECT DeviceObject, PIRP irp) {
		UNREFERENCED_PARAMETER(DeviceObject);

		irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}*/

	NTSTATUS create(PDEVICE_OBJECT DeviceObject, PIRP irp) {
		UNREFERENCED_PARAMETER(DeviceObject);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	NTSTATUS close(PDEVICE_OBJECT DeviceObject, PIRP irp) {
		UNREFERENCED_PARAMETER(DeviceObject);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	//TODO
	NTSTATUS device_control(PDEVICE_OBJECT DeviceObject, PIRP irp) {
		UNREFERENCED_PARAMETER(DeviceObject);

		DebugPrint("[+] Device control called.\n");

		NTSTATUS status = STATUS_UNSUCCESSFUL;


		// used to determine ctl code
		PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);

		// access the request object that um sents
		auto request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);

		if (stack_irp == nullptr or request == nullptr) {
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}

		// process we want access to (rw)
		static PEPROCESS TargetProcess = nullptr;

		const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;
		switch (control_code) {
			case codes::attach:
				status = PsLookupProcessByProcessId(request->ProcessId, &TargetProcess);
				break;

			case codes::read:
				if (TargetProcess != nullptr) {
					status = MmCopyVirtualMemory(TargetProcess, request->pTarget,
												 PsGetCurrentProcess(), request->pBuffer,
												 request->BufferSize, KernelMode, &request->ReturnSize);
				}
				break;

			case codes::write:
				if (TargetProcess != nullptr) {
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), request->pBuffer,
												 TargetProcess, request->pTarget, request->BufferSize, 
												 KernelMode, &request->ReturnSize);
				}
				break;

			default:
				break;
		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(Request);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

} // namespace driver

/**
 * @brief Initialize driver
 * @param DriverObject Driver object
 * @param RegistryPath Path to registry key with driver parameters. Never used.
 * @return 
 */
NTSTATUS DriverMain(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	//create device
	UNICODE_STRING device_name = {};
	RtlInitUnicodeString(&device_name, L"\\Device\\MemscanDriver");

	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &device_name, FILE_DEVICE_UNKNOWN,
									 FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

	if (status != STATUS_SUCCESS) {
		DebugPrint("[-] Failed to create driver device.\n");
	}
	DebugPrint("[+] Driver device successfully created.\n");

	// establish symbolic link
	UNICODE_STRING symbolic_link = {};
	RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\MemscanDriver");

	status = IoCreateSymbolicLink(&symbolic_link, &device_name);
	if (status != STATUS_SUCCESS) {
		DebugPrint("[-] Failed to establish symbolic link.\n");
	}
	DebugPrint("[+] Symbolic link was established successfully.\n");

	// allow to send small data between um&km
	SetFlag(DeviceObject->Flags, DO_BUFFERED_IO);

	// set the driver handlers to our functions with our logic
	DriverObject->MajorFunction[IRP_MJ_CREATE] = driver::create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = driver::close;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

	// end of initialization
	ClearFlag(DeviceObject->Flags, DO_DEVICE_INITIALIZING);

	DebugPrint("[+] Driver initialized successfully.\n");

	return status;
}

/**
 * @brief Trunc function for KdMapper
 * @return 
 */
NTSTATUS DriverEntry() {
	DebugPrint("[+] Message from the driver!\n");

	UNICODE_STRING driver_name = {};
	RtlInitUnicodeString(&driver_name, L"\\Driver\\MemscanDriver");

	return IoCreateDriver(&driver_name, &DriverMain);
}