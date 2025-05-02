#include <ntifs.h>

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

NTSTATUS DriverEntry() {
	DebugPrint("[+] Message from kernel!");
	return STATUS_SUCCESS;
}