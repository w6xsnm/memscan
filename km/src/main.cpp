#include "memscan.h"

//////////////////////////////// UTULITIES /////////////////////////////////////

/**
 * @brief Prints debug message
 * @param format 
 * @param  
 */
void DebugPrint(PCSTR format, ...) {
#ifndef DEBUG
	UNREFERENCED_PARAMETER(format);
#endif
	va_list args;
	va_start(args, format);

	// For simple string case (no format specifiers)
	if (strchr(format, '%') == NULL) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "%s", format));
	}
	else {
		// For formatted output
		vDbgPrintExWithPrefix(
			"[DRIVER] ",  // Optional prefix
			DPFLTR_IHVDRIVER_ID,
			DPFLTR_INFO_LEVEL,
			format,
			args
		);
	}

	va_end(args);
}

/**
 * @brief Retrieves the PEB of a process
 * @param Process Target process PEPROCESS
 * @param[out] peb Pointer to store PEB address
 * @return NTSTATUS success/error code
 */
NTSTATUS GetProcessPeb(PEPROCESS Process, PPEB* peb) {
	if (!Process || !peb) {
		DebugPrint("[-] GetProcessPeb: Invalid parameters.\n");
		return STATUS_INVALID_PARAMETER;
	}

	*peb = PsGetProcessPeb(Process);
	if (!*peb) {
		DebugPrint("[-] GetProcessPeb: Failed to get PEB.\n");
		return STATUS_NOT_FOUND;
	}

	return STATUS_SUCCESS;
}

/**
 * @brief Gets the base address of a loaded module by name
 * @param peb Process PEB structure
 * @param moduleName Name of the module to find (e.g. "ntdll.dll")
 * @param[out] imageBase Base address of the module
 * @return NTSTATUS success/error code
 */
NTSTATUS GetModuleBaseByName(PPEB peb, PCWSTR moduleName, PVOID* imageBase)
{
	if (!peb || !peb->Ldr || !moduleName || !imageBase) {
		DebugPrint("[-] GetModuleBaseByName: Invalid parameters.\n");
		return STATUS_INVALID_PARAMETER;
	}

	*imageBase = nullptr;
	PLIST_ENTRY listHead = &peb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY listEntry = listHead->Flink;

	while (listEntry != listHead) {
		PLDR_DATA_TABLE_ENTRY moduleEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (moduleEntry->BaseDllName.Buffer) {
			DebugPrint("[+] Found module: %wZ (Base: 0x%p)\n", &moduleEntry->BaseDllName, moduleEntry->DllBase);
			if (_wcsicmp(moduleEntry->BaseDllName.Buffer, moduleName) == 0) {
				*imageBase = moduleEntry->DllBase;
				DebugPrint("[+] Target module %wZ found at 0x%p\n", &moduleEntry->BaseDllName, *imageBase);
				return STATUS_SUCCESS;
			}
		}
		listEntry = listEntry->Flink;
	}

	DebugPrint("[-] Module %ws not found.\n");
	return STATUS_NOT_FOUND;
}

/**
 * @brief Retrieves DOS header from module base
 * @param Process Target process PEPROCESS
 * @param imageBase Module base address
 * @param[out] dosHeader DOS header structure
 * @return NTSTATUS success/error code
 */
NTSTATUS GetDosHeader(PEPROCESS Process, PVOID imageBase, PIMAGE_DOS_HEADER dosHeader) {
	if (!Process || !imageBase || !dosHeader) {
		DebugPrint("[-] GetDosHeader: Invalid parameters\n");
		return STATUS_INVALID_PARAMETER; 
	}

	SIZE_T bytesRead = 0;
	NTSTATUS status = MmCopyVirtualMemory(
		Process,
		imageBase,
		PsGetCurrentProcess(),
		dosHeader,
		sizeof(IMAGE_DOS_HEADER),
		KernelMode,
		&bytesRead
	);

	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] GetDosHeader: MmCopyVirtualMemory failed.\n");
		return status;
	}

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		DebugPrint("[-] GetDosHeader: Invalid DOS signature.\n");
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	DebugPrint("[+] GetDosHeader: Valid DOS header (Signature: 0x%X)\n", dosHeader->e_magic);
	return STATUS_SUCCESS;
}

/**
 * @brief Retrieves NT headers from module base
 * @param Process Target process PEPROCESS
 * @param imageBase Module base address
 * @param dosHeader DOS header structure
 * @param[out] ntHeaders NT headers structure
 * @return NTSTATUS success/error code
 */
NTSTATUS GetNtHeaders(PEPROCESS Process, PVOID imageBase,
	PIMAGE_DOS_HEADER dosHeader, PIMAGE_NT_HEADERS64 ntHeaders) {
	if (!Process || !imageBase || !dosHeader || !ntHeaders) {
		DebugPrint("[-] GetNtHeaders: Invalid parameters\n");
		return STATUS_INVALID_PARAMETER;
	}

	PVOID ntHeaderAddr = (PBYTE)imageBase + dosHeader->e_lfanew;
	SIZE_T bytesRead = 0;

	NTSTATUS status = MmCopyVirtualMemory(
		Process,
		ntHeaderAddr,
		PsGetCurrentProcess(),
		ntHeaders,
		sizeof(IMAGE_NT_HEADERS64),
		KernelMode,
		&bytesRead
	);

	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] GetNtHeaders: MmCopyVirtualMemory failed.\n");
		return status;
	}

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		DebugPrint("[-] GetNtHeaders: Invalid NT signature.\n");
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	DebugPrint("[+] GetNtHeaders: Valid NT headers (Segnature: 0x%X, Sections: %d, ImageSize: 0x%X)\n",
		ntHeaders->Signature,
		ntHeaders->FileHeader.NumberOfSections,
		ntHeaders->OptionalHeader.SizeOfImage);
	return STATUS_SUCCESS;
}

/**
 * @brief Gets base address of a section by name (analog to PoC version)
 * @param baseAddress Module base address
 * @param name Section name (e.g. ".mrdata")
 * @return PVOID Section base address or NULL if not found
 */
PVOID GetSectionBase(PVOID baseAddress, const char* name) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((ULONG_PTR)baseAddress + dosHeader->e_lfanew);

	// Validate PE headers
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		DebugPrint("[-] GetSectionBase: Invalid DOS signature (0x%X)\n", dosHeader->e_magic);
		return nullptr;
	}

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		DebugPrint("[-] GetSectionBase: Invalid NT signature (0x%X)\n", ntHeaders->Signature);
		return nullptr;
	}

	// Calculate section headers pointer
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(
									 (ULONG_PTR)ntHeaders +
						             sizeof(IMAGE_NT_HEADERS64) -
									 sizeof(IMAGE_OPTIONAL_HEADER64) + ntHeaders->FileHeader.SizeOfOptionalHeader);

	DebugPrint("[+] GetSectionBase: Scanning %d sections in module 0x%p\n", ntHeaders->FileHeader.NumberOfSections, baseAddress);

	// Scan sections
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		DebugPrint("    [%d] %-8s  RVA: 0x%08X  Size: 0x%08X\n",
			i,
			sections[i].Name,
			sections[i].VirtualAddress,
			sections[i].Misc.VirtualSize);

		if (strncmp(name, (const char*)sections[i].Name, 8) == 0) {
			PVOID sectionBase = (PBYTE)baseAddress + sections[i].VirtualAddress;
			DebugPrint("[+] Found section %s at 0x%p (Size: 0x%X)\n",
				name,
				sectionBase,
				sections[i].Misc.VirtualSize);
			return sectionBase;
		}
	}

	DebugPrint("[-] Section %s not found\n", name);
	return nullptr;
}


/////////////////////////////// DRIVER ////////////////////////////////////////////

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

	// EDR pointers
	static PBYTE gAvrfpEnabled = nullptr;
	static PBYTE gAvrfpRoutine = nullptr;
	static PBYTE gShimLoaded = nullptr;

	// Forward declarations for notifications
	VOID ScanProcess(PEPROCESS Process);
	VOID OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
	VOID OnImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
	BOOLEAN IsSystemProcess(PEPROCESS Process);
	VOID ComputeEdrAddresses(PEPROCESS Process);
	VOID CheckEdrIndicators(PEPROCESS Process);

	// Log IOC
	static void LogIoc(_In_ PCSTR msg) {
		if (driver::IocCount < IOC_MAX_ENTRIES) {
			SIZE_T len = strlen(msg);
			if (len >= IOC_MESSAGE_SIZE) len = IOC_MESSAGE_SIZE - 1;
			RtlCopyMemory(driver::IocBuffer[driver::IocCount], msg, len);
			driver::IocBuffer[driver::IocCount][len] = '\0';
			driver::IocCount++;
		}
	}

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

/**
 * @brief Cleanup callback when driver unloads
 */
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	DebugPrint("[+] Unloading driver, unregistering callbacks...\n");

	NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(driver::OnProcessNotify, TRUE);
	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] Failed to unregister process notify.\n");
	}
	DebugPrint("[+] Process notify unregistered.\n");

	status = PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)driver::OnImageLoadNotify);
	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] Failed to unregister load image notify.\n");
	}
	DebugPrint("[+] Load image notify unregistered.\n");

	status = IoDeleteSymbolicLink(&gSymLinkName);
	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] Failed to delete symbolic link.\n");
	}
	DebugPrint("[+] Symbolic link deleted.\n");

	IoDeleteDevice(gDeviceObject);

	DebugPrint("[+] Driver successfully unloaded.\n");
}

/**
 * @brief Initialize driver
 * @param DriverObject Driver object
 * @param RegistryPath Path to registry key with driver parameters. Never used.
 * @return 
 */
NTSTATUS DriverMain(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	DebugPrint("[+] Entering driver main.\n");

	// Create device
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &gDeviceName, FILE_DEVICE_UNKNOWN,
									 FILE_DEVICE_SECURE_OPEN, FALSE, &gDeviceObject);

	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] Failed to create driver device.\n");
	}
	DebugPrint("[+] Driver device successfully created.\n");

	// Establish symbolic link
	status = IoCreateSymbolicLink(&gSymLinkName, (PUNICODE_STRING)&gDeviceName);
	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] Failed to establish symbolic link.\n");
	}
	DebugPrint("[+] Symbolic link was established successfully.\n");

	// Allow to send small data between um&km
	SetFlag(gDeviceObject->Flags, DO_BUFFERED_IO);

	// Set IRP handlers
	DriverObject->MajorFunction[IRP_MJ_CREATE] = driver::create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = driver::close;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;
	DriverObject->DriverUnload = DriverUnload;

	// Register notifications
	PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)driver::OnProcessNotify, FALSE);
	PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)driver::OnImageLoadNotify);

	// End of initialization
	ClearFlag(gDeviceObject->Flags, DO_DEVICE_INITIALIZING);

	DebugPrint("[+] Driver initialized successfully.\n");

	return status;
}

/**
 * @brief Trampoline entry for KdMapper
 * @return 
 */
NTSTATUS DriverEntry() {
	DebugPrint("[+] Message from the driver!\n");

	NTSTATUS status = IoCreateDriver(&gDriverName, &DriverMain);
	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] Failed to create a driver.\n");
		return status;
	}
	DebugPrint("[+] Driver has created successfully.\n");
	return status;

}

///////////////////////// SCANNING ////////////////////////////////

/**
 * @brief Called on process creation or termination
 */
VOID driver::OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(CreateInfo);
	ScanProcess(Process);
}

/**
 * @brief Called on image load into process
 */
VOID driver::OnImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
	UNREFERENCED_PARAMETER(FullImageName);
	UNREFERENCED_PARAMETER(ImageInfo);
	PEPROCESS proc = nullptr;
	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &proc))) {
		ScanProcess(proc);
		ObDereferenceObject(proc);
	}
}

/**
 * @brief Primary scan routine for a given process
 */
VOID driver::ScanProcess(PEPROCESS Process) {
	if (IsSystemProcess(Process))
		return;
	ComputeEdrAddresses(Process);
	CheckEdrIndicators(Process);
	// TODO: invoke VAD and module scans here
}

/**
 * @brief Determine if target process is a system process
 */
BOOLEAN driver::IsSystemProcess(PEPROCESS Process) {
	ULONG pid = (ULONG)(ULONG_PTR)PsGetProcessId(Process);
	ULONG sid = PsGetProcessSessionId(Process);
	if (pid < 100 || sid == 0)
		return TRUE;
	// Compare process image name against whitelist
	PUNICODE_STRING imgName = nullptr;
	NTSTATUS status = SeLocateProcessImageName(Process, &imgName);
	if (NT_SUCCESS(status) && imgName) {
		for (const wchar_t** wp = SystemProcessWhitelist; *wp; ++wp) {
			UNICODE_STRING w;
			RtlInitUnicodeString(&w, *wp);
			if (RtlEqualUnicodeString(imgName, &w, TRUE)) {
				DebugPrint("[+] System process occured.\n");
				ExFreePool(imgName);
				return TRUE;
			}
		}
		ExFreePool(imgName);
	}
	return FALSE;
}

/**
* @brief Locates EDR-related addresses in ntdll.dll's .mrdata section
* @param Process Target process PEPROCESS
*/
VOID driver::ComputeEdrAddresses(PEPROCESS Process) {
	DebugPrint("[+] ComputeEdrAddresses: Starting ntdll.dll .mrdata scan\n");

	// 0. Get process name for debug only
	PUNICODE_STRING processName = nullptr;
	NTSTATUS nameStatus = SeLocateProcessImageName(Process, &processName);
	if (NT_SUCCESS(nameStatus) && processName) {
		DebugPrint("[+] Scanning process: %wZ\n", processName);
		ExFreePool(processName);
	}
	else {
		DebugPrint("[+] Scanning process (PID: %d)\n", PsGetProcessId(Process));
	}


	// 1. Get process PEB
	PPEB peb = nullptr;
	NTSTATUS status = GetProcessPeb(Process, &peb);
	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] ComputeEdrAddresses: Failed to get PEB.\n");
		return;
	}

	// 2. Get ntdll.dll base address
	PVOID ntdllBase = nullptr;
	status = GetModuleBaseByName(peb, L"ntdll.dll", &ntdllBase);
	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] ComputeEdrAddresses: Failed to find ntdll.dll.\n");
		return;
	}

	// 3. Get DOS header
	IMAGE_DOS_HEADER dosHeader = { 0 };
	status = GetDosHeader(Process, ntdllBase, &dosHeader);
	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] ComputeEdrAddresses: Invalid ntdll.dll DOS header.\n");
		return;
	}

	// 4. Get NT headers
	IMAGE_NT_HEADERS64 ntHeaders = { 0 };
	status = GetNtHeaders(Process, ntdllBase, &dosHeader, &ntHeaders);
	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] ComputeEdrAddresses: Invalid ntdll.dll NT headers.\n");
		return;
	}

	// 5. Find .mrdata section
	PVOID mrdataBase = GetSectionBase(ntdllBase, ".mrdata");
	if (!mrdataBase) {
		DebugPrint("[-] ComputeEdrAddresses: .mrdata section not found in ntdll.dll\n");
		return;
	}

	// 6. Scan for EDR patterns in .mrdata
	DebugPrint("[+] ComputeEdrAddresses: Scanning .mrdata for EDR indicators...\n");

	//SIZE_T step = sizeof(PVOID);
	//for (SIZE_T i = 0; i < mrdataSize / step; ++i) {
	//	PVOID cand = nullptr;
	//	SIZE_T bytesRead = 0;
	//	NTSTATUS status1 = MmCopyVirtualMemory(Process, mrdataBase + i * step,
	//										  PsGetCurrentProcess(), &cand,
	//										  step, KernelMode, &bytesRead);
	//	if (!NT_SUCCESS(status1)) break;
	//	if (cand == mrdataBase) {
	//		PBYTE pmr = mrdataBase + i * step;
	//		// Find AvrfpEnabled and AvrfpRoutine
	//		for (SIZE_T j = 1; j < mrdataSize / step; ++j) {
	//			PVOID val = nullptr;
	//			NTSTATUS status2 = MmCopyVirtualMemory(Process, pmr + j * step,
	//												   PsGetCurrentProcess(), &val,
	//												   step, KernelMode, &bytesRead);
	//			if (!NT_SUCCESS(status2)) break;
	//			if (val == NULL) {
	//				driver::gAvrfpEnabled = pmr + (j - 1) * step;
	//				driver::gAvrfpRoutine = pmr + j * step;
	//				DebugPrint("[+] AvrfpEnabled, AvrfpRoutine finded.\n");
	//				break;
	//			}
	//		}
	//		// Find ShimLoaded pointer
	//		for (SIZE_T j = 1; j < mrdataSize / step; ++j) {
	//			SIZE_T val = 0;
	//			status = MmCopyVirtualMemory(Process, pmr - j * step,
	//										 PsGetCurrentProcess(), &val,
	//										 step, KernelMode, &bytesRead);
	//			if (val == mrdataSize) {
	//				driver::gShimLoaded = pmr - (j + 1) * step;
	//				DebugPrint("[+] ShimLoaded finded.\n");
	//				break;
	//			}
	//		}
	//		break;
	//	}
	//}

	//DebugPrint("[+] ComputeEdrAddresses: completed");
}


/**
 * @brief Check if any EDR hooks or preloader flags are set
 */
VOID driver::CheckEdrIndicators(PEPROCESS Process) {
	UNREFERENCED_PARAMETER(Process);
	DebugPrint("[+] CheckEdrIndicators stub.\n");

	SIZE_T bytesRead = 0;
	NTSTATUS status;
	BOOLEAN enabled = FALSE;
	PVOID routine = nullptr;
	PVOID shim = nullptr;

	// Check AvrfpAPILookupCallbacksEnabled
	if (driver::gAvrfpEnabled) {
		status = MmCopyVirtualMemory(Process, driver::gAvrfpEnabled,
									 PsGetCurrentProcess(), &enabled,
									 sizeof(enabled), KernelMode, &bytesRead);
		if (status == STATUS_SUCCESS && enabled) {
			DebugPrint("[+] CheckEdrIndicators: AvrfpAPILookupCallbacksEnabled is TRUE.\n");
			LogIoc("[EDR] AvrfpAPILookupCallbacksEnabled true");
		}
	}

	// Check AvrfpAPILookupCallbackRoutine
	if (driver::gAvrfpRoutine) {
		status = MmCopyVirtualMemory(Process, driver::gAvrfpRoutine,
									 PsGetCurrentProcess(), &routine,
									 sizeof(routine), KernelMode, &bytesRead);
		if (status == STATUS_SUCCESS && routine) {
			DebugPrint("[+] CheckEdrIndicators: AvrfpAPILookupCallbackRoutine is non-null.\n");
				LogIoc("[EDR] AvrfpAPILookupCallbackRoutine hooked");
		}
	}

	// Check Shim loaded callback
	if (driver::gShimLoaded) {
		status = MmCopyVirtualMemory(Process, driver::gShimLoaded,
									 PsGetCurrentProcess(), &shim,
									 sizeof(shim), KernelMode, &bytesRead);
		if (status == STATUS_SUCCESS && shim) {
			DebugPrint("[+] CheckEdrIndicators: g_pfnSE_DllLoaded is non-null.\n");
			LogIoc("[EDR] g_pfnSE_DllLoaded hooked");
		}
	}
}
