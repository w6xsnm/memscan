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

// IOC (Indicators of Compromise) buffer constants
#define IOC_MAX_ENTRIES    512
#define IOC_MESSAGE_SIZE   128

// IOCTL control codes
#define IOCTL_ATTACH_PROCESS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_READ_MEMORY      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_WRITE_MEMORY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GET_IOC_BUFFER   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x699, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_CLEAR_IOC_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x69A, METHOD_BUFFERED, FILE_WRITE_DATA)

// Global device, driver and symbolic link names
static PDEVICE_OBJECT gDeviceObject = nullptr;
static UNICODE_STRING gDeviceName = RTL_CONSTANT_STRING(L"\\Device\\MemscanDriver");
static UNICODE_STRING gDriverName = RTL_CONSTANT_STRING(L"\\Driver\\MemscanDriver");
static UNICODE_STRING gSymLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\MemscanDriver");

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
		constexpr ULONG attach = IOCTL_ATTACH_PROCESS;		// Setup the driver
		constexpr ULONG read = IOCTL_READ_MEMORY;			// Read process memory
		constexpr ULONG write = IOCTL_WRITE_MEMORY;			// Write process memory
		constexpr ULONG get_ioc = IOCTL_GET_IOC_BUFFER;		// Copy ioc to um
		constexpr ULONG clear_ioc = IOCTL_CLEAR_IOC_BUFFER;	// Clear ioc buffer and counter 

	} //namespace codes

	// Shared between um & km for IOCTL
	struct Request {
		HANDLE ProcessId;

		PVOID pTarget;
		PVOID pBuffer;

		SIZE_T BufferSize;
		SIZE_T ReturnSize;
	};

	// IOC log buffer
	static CHAR IocBuffer[IOC_MAX_ENTRIES][IOC_MESSAGE_SIZE];
	static ULONG IocCount = 0;

	// Last attached process for read/write
	static PEPROCESS TargetProcess = nullptr;

	// Forward declarations for notifications
	//VOID ScanProcess(PEPROCESS Process);
	//VOID OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
	//VOID OnImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);

	//IRP major functions

	/*NTSTATUS unsupported(PDEVICE_OBJECT DeviceObject, PIRP irp) {
		UNREFERENCED_PARAMETER(DeviceObject);

		irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}*/

	/**
	 * @brief Handle create calls
	 * @param DeviceObject Never used
	 * @param irp Request
	 * @return 
	 */
	NTSTATUS create(PDEVICE_OBJECT DeviceObject, PIRP irp) {
		UNREFERENCED_PARAMETER(DeviceObject);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	/**
	 * @brief Handle close calls
	 * @param DeviceObject Never used
	 * @param irp Request
	 * @return 
	 */
	NTSTATUS close(PDEVICE_OBJECT DeviceObject, PIRP irp) {
		UNREFERENCED_PARAMETER(DeviceObject);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	/**
	 * @brief Handle DeviceIoControl requests
	 * @param DeviceObject Never used
	 * @param irp Request
	 * @return 
	 */
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

			DebugPrint("[-] Failed to get stack irp or request.\n");
			return status;
		}

		const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;
		switch (control_code) {
			case codes::attach:
				status = PsLookupProcessByProcessId(request->ProcessId, &TargetProcess);
				break;

			case codes::read:
				if (TargetProcess) {
					status = MmCopyVirtualMemory(TargetProcess, request->pTarget,
												 PsGetCurrentProcess(), request->pBuffer,
												 request->BufferSize, KernelMode, &request->ReturnSize);
				}
				break;

			case codes::write:
				if (TargetProcess) {
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), request->pBuffer,
												 TargetProcess, request->pTarget, request->BufferSize, 
												 KernelMode, &request->ReturnSize);
				}
				break;

			case codes::get_ioc:
				{
					ULONG toCopy = min(IocCount * IOC_MESSAGE_SIZE,
									   stack_irp->Parameters.DeviceIoControl.OutputBufferLength);
					RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, IocBuffer, toCopy);

					status = irp->IoStatus.Status;
				}
				break;

			case codes::clear_ioc: 
				{
					IocCount = 0;
					RtlZeroMemory(IocBuffer, sizeof(IocBuffer));

					status = irp->IoStatus.Status;
				}
				break;

			default:
				status = STATUS_INVALID_DEVICE_REQUEST;
				break;
		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(Request);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

} // namespace driver

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	//PsSetCreateProcessNotifyRoutineEx(driver::OnProcessNotify, TRUE);
	//PsRemoveLoadImageNotifyRoutine(driver::OnImageLoadNotify);
	IoDeleteSymbolicLink(&gSymLinkName);
	IoDeleteDevice(gDeviceObject);
}

/**
 * @brief Initialize driver
 * @param DriverObject Driver object
 * @param RegistryPath Path to registry key with driver parameters. Never used.
 * @return 
 */
NTSTATUS DriverMain(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	// Create device
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &gDeviceName, FILE_DEVICE_UNKNOWN,
									 FILE_DEVICE_SECURE_OPEN, FALSE, &gDeviceObject);

	if (status != STATUS_SUCCESS) {
		DebugPrint("[-] Failed to create driver device.\n");
	}
	DebugPrint("[+] Driver device successfully created.\n");

	// Establish symbolic link
	status = IoCreateSymbolicLink(&gSymLinkName, &gDeviceName);
	if (status != STATUS_SUCCESS) {
		DebugPrint("[-] Failed to establish symbolic link.\n");
	}
	DebugPrint("[+] Symbolic link was established successfully.\n");

	// Allow to send small data between um&km
	SetFlag(gDeviceObject->Flags, DO_BUFFERED_IO);

	// Set IRP handlers
	DriverObject->MajorFunction[IRP_MJ_CREATE] = driver::create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = driver::close;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

	// Register notifications
	//PsSetCreateProcessNotifyRoutineEx(driver::OnProcessNotify, FALSE);
	//PsSetLoadImageNotifyRoutine(driver::OnImageLoadNotify);

	// End of initialization
	ClearFlag(gDeviceObject->Flags, DO_DEVICE_INITIALIZING);

	DebugPrint("[+] Driver initialized successfully.\n");

	return status;
}

/**
 * @brief Trunc function for KdMapper
 * @return 
 */
NTSTATUS DriverEntry() {
	DebugPrint("[+] Message from the driver!\n");

	return IoCreateDriver(&gDriverName, &DriverMain);
}