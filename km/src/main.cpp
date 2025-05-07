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
	vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, format, args);
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

	DebugPrint("[+] GetNtHeaders: Valid NT headers (Signature: 0x%X, Sections: %d, ImageSize: 0x%X)\n",
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
SectionInfo GetSectionInfo(PVOID moduleBase, const char* sectionName) {
	SectionInfo info = { nullptr, 0 };
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((ULONG_PTR)moduleBase + dosHeader->e_lfanew);

	// Validate PE headers
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		DebugPrint("[-] GetSectionInfo: Invalid DOS signature (0x%X)\n", dosHeader->e_magic);
		return info;
	}

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		DebugPrint("[-] GetSectionInfo: Invalid NT signature (0x%X)\n", ntHeaders->Signature);
		return info;
	}

	//// Calculate section headers pointer
	//PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(
	//								 (ULONG_PTR)ntHeaders +
	//					             sizeof(IMAGE_NT_HEADERS64) -
	//								 sizeof(IMAGE_OPTIONAL_HEADER64) + ntHeaders->FileHeader.SizeOfOptionalHeader);

	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);

	DebugPrint("[+] GetSectionInfo: Scanning %d sections in module 0x%p\n", ntHeaders->FileHeader.NumberOfSections, moduleBase);

	// Scan sections
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		DebugPrint("    [%d] %-8s  RVA: 0x%08X  Size: 0x%08X\n",
			i,
			sections[i].Name,
			sections[i].VirtualAddress,
			sections[i].Misc.VirtualSize);

		if (strncmp(sectionName, (const char*)sections[i].Name, 8) == 0) {
			info.Base = (PBYTE)moduleBase + sections[i].VirtualAddress;
			info.Size = sections[i].Misc.VirtualSize;
			DebugPrint("[+] Found section %s at 0x%p (Size: 0x%X)\n",
				sectionName,
				info.Base,
				sections[i].Misc.VirtualSize);
			return info;
		}
	}

	DebugPrint("[-] Section %s not found\n", sectionName);
	return info;
}

/**
 * @brief Checks if a pointer in target process contains non-NULL value
 * @param Process Target process PEPROCESS
 * @param remoteAddress Address to check in target process
 * @param isBoolean TRUE for BOOLEAN checks, FALSE for PVOID checks
 * @param pointerName Name of pointer for debug messages
 * @return TRUE if value exists and is non-zero/NULL
 */
BOOLEAN CheckPointerValue(PEPROCESS Process, PVOID remoteAddress, BOOLEAN isBoolean) {
	if (!remoteAddress) {
		DebugPrint("[-] Pointer is NULL (skipping check).\n");
		return FALSE;
	}

	SIZE_T bytesRead = 0;
	NTSTATUS status;
	BOOLEAN result = FALSE;

	if (isBoolean) {
		BOOLEAN enabled = FALSE;
		status = MmCopyVirtualMemory(Process, remoteAddress,
									 PsGetCurrentProcess(), &enabled,
									 sizeof(BOOLEAN), KernelMode, &bytesRead);
		if (!NT_SUCCESS(status)) {
			DebugPrint("[-] Failed to read BOOLEAN (Status: 0x%X, Bytes: %zu)\n", status, bytesRead);
			return FALSE;
		}
		result = enabled;
	}
	else {
		PVOID pointerValue = nullptr;
		status = MmCopyVirtualMemory(Process, remoteAddress,
									 PsGetCurrentProcess(), &pointerValue,
							         sizeof(PVOID), KernelMode, &bytesRead);
		if (!NT_SUCCESS(status)) {
			DebugPrint("[-] Failed to read pointer (Status: 0x%X, Bytes: %zu)\n", status, bytesRead);
			return FALSE;
		}
		result = (pointerValue != nullptr);
	}
	return result;
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
	static PBYTE gpfnSE_DllLoaded = nullptr;

	// Forward declarations for notifications
	VOID ScanProcess(PEPROCESS Process);
	VOID OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
	VOID OnImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
	BOOLEAN IsSystemProcess(PEPROCESS Process);
	VOID CheckMrdataAddresses(PEPROCESS Process);

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
	CheckMrdataAddresses(Process);
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

	PUNICODE_STRING imgName = nullptr;
	NTSTATUS status = SeLocateProcessImageName(Process, &imgName);
	if (!NT_SUCCESS(status) || !imgName) {
		return FALSE;
	}

	BOOLEAN isWhitelisted = FALSE;

	for (const wchar_t** wp = SystemProcessWhitelist; *wp; ++wp) {
		// Используем FsRtlIsNameInExpression для поддержки wildcards
		UNICODE_STRING pattern;
		RtlInitUnicodeString(&pattern, *wp);

		if (FsRtlIsNameInExpression(&pattern, imgName, TRUE, NULL)) {
			DebugPrint("[+] Whitelisted process: %wZ (matches pattern: %wZ)\n",
				imgName, &pattern);
			isWhitelisted = TRUE;
			break;
		}
	}

	ExFreePool(imgName);
	return isWhitelisted;
}

/**
* @brief Locates EDR-related addresses in ntdll.dll's .mrdata section
* @param Process Target process PEPROCESS
*/
VOID driver::CheckMrdataAddresses(PEPROCESS Process) {
	DebugPrint("[+] CheckMrdataAddresses: Starting ntdll.dll .mrdata scan\n");

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
		DebugPrint("[-] CheckMrdataAddresses: Failed to get PEB.\n");
		return;
	}

	// 2. Get ntdll.dll base address
	PVOID ntdllBase = nullptr;
	status = GetModuleBaseByName(peb, L"ntdll.dll", &ntdllBase);
	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] CheckMrdataAddresses: Failed to find ntdll.dll.\n");
		return;
	}

	// 3. Get DOS header
	IMAGE_DOS_HEADER dosHeader = { 0 };
	status = GetDosHeader(Process, ntdllBase, &dosHeader);
	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] CheckMrdataAddresses: Invalid ntdll.dll DOS header.\n");
		return;
	}

	// 4. Get NT headers
	IMAGE_NT_HEADERS64 ntHeaders = { 0 };
	status = GetNtHeaders(Process, ntdllBase, &dosHeader, &ntHeaders);
	if (!NT_SUCCESS(status)) {
		DebugPrint("[-] CheckMrdataAddresses: Invalid ntdll.dll NT headers.\n");
		return;
	}

	// 5. Find .mrdata section
	SectionInfo mrdata = GetSectionInfo(ntdllBase, ".mrdata");
	if (!mrdata.Base) {
		DebugPrint("[-] CheckMrdataAddresses: .mrdata section not found in ntdll.dll\n");
		return;
	}

	// 6. Scan for EDR preloading and Early Cascade patterns in .mrdata

	SIZE_T step = sizeof(PVOID);

	// EDR Preloading indicators

	for (SIZE_T i = 0; i < mrdata.Size / step; ++i) {
		PVOID candidate = nullptr;
		SIZE_T bytesRead = 0;

		NTSTATUS status1 = MmCopyVirtualMemory(Process, (PBYTE)mrdata.Base + i * step,
												  PsGetCurrentProcess(), &candidate,
												  step, KernelMode, &bytesRead);

		if (!NT_SUCCESS(status1) || bytesRead != step) {
			DebugPrint("[-] MmCopyVirtualMemory failed at 0x%p (Status: 0x%X, Bytes: %zu)\n", (PBYTE)mrdata.Base + i * step, status1, bytesRead);
			continue;
		}

		if (candidate == mrdata.Base) {
			DebugPrint("[+] Found self-reference at offset 0x%X (Value: 0x%p)\n", i * step, candidate);

			PBYTE pmr = (PBYTE)mrdata.Base + i * step; // self-reference variable on mrdata is perfect indicator

			// AvrfpEnabled/AvrfpRoutine
			for (SIZE_T j = 1; j < 3; ++j) {
				PVOID val = nullptr;
				NTSTATUS status2 = MmCopyVirtualMemory(Process, pmr + j * step, PsGetCurrentProcess(),
													   &val, step, KernelMode, &bytesRead);
				if (NT_SUCCESS(status2)) {
					DebugPrint("    [%zu] Candidate at 0x%p: 0x%p\n", j, pmr + j * step, val);

					if (val == nullptr) {
						driver::gAvrfpEnabled = pmr + (j - 1) * step;
						driver::gAvrfpRoutine = pmr + j * step;
						DebugPrint("[+] Found EDR pointers:\n"
							"    AvrfpEnabled: 0x%p\n"
							"    AvrfpRoutine: 0x%p\n",
							driver::gAvrfpEnabled,
							driver::gAvrfpRoutine);
					}
				}
			}
		}
	}

	// Early Cascade Injection 

	PBYTE searchStart = (PBYTE)driver::gAvrfpEnabled - 0x100; // offset based on heuristics, does not important

	for (int i = 0; i < 100; i++) { // heuristic based index just not to enter endless cycle
		PBYTE candidate = searchStart - (i * sizeof(PVOID));
		PVOID value = nullptr;
		SIZE_T bytesRead = 0;

		NTSTATUS status3 = MmCopyVirtualMemory(Process, candidate,
											   PsGetCurrentProcess(), &value,
											   sizeof(PVOID), KernelMode, &bytesRead);
		if (NT_SUCCESS(status3)) {
			DebugPrint("[+] Found gpfnSE_DllLoaded candidate @ 0x%p (Value: 0x%p)", candidate, value);
			// Check if that looks like function offset
			if ((ULONG_PTR)value > (ULONG_PTR)ntdllBase &&
				(ULONG_PTR)value < ((ULONG_PTR)ntdllBase + 0x200000)) {
				driver::gpfnSE_DllLoaded = candidate;
				DebugPrint("[+] Found gpfnSE_DllLoaded that looks like function @ 0x%p (Value: 0x%p)", candidate, value);
				break;
			}
		}
	}

	if (CheckPointerValue(Process, driver::gAvrfpEnabled, TRUE)) {
		DebugPrint("[+] AvrfpAPILookupCallbacksEnabled is TRUE\n");
		LogIoc("[EDR] AvrfpAPILookupCallbacksEnabled true");
	}

	// Проверка AvrfpRoutine (PVOID)
	if (CheckPointerValue(Process, driver::gAvrfpRoutine, FALSE)) {
		DebugPrint("[+] AvrfpAPILookupCallbackRoutine is hooked\n");
		LogIoc("[EDR] AvrfpAPILookupCallbackRoutine hooked");
	}

	// Проверка gpfnSE_DllLoaded (PVOID)
	if (CheckPointerValue(Process, driver::gpfnSE_DllLoaded, FALSE)) {
		DebugPrint("[+] gpfnSE_DllLoaded is hooked\n");
		LogIoc("[EDR] gpfnSE_DllLoaded hooked");
	}

	DebugPrint("[+] EDR scan completed for process PID: %d\n", PsGetProcessId(Process));
}