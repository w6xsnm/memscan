#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <minwindef.h>
#include <stdarg.h>

//undocumented windows internal functions (exported by ntoskrnl)
extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName,
		PDRIVER_INITIALIZE InitializaionFunction);
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
		PEPROCESS TargetProcess, PVOID TargetAddress,
		SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize);
	NTKERNELAPI ULONG PsGetProcessSessionId(PEPROCESS Process);
	NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
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
extern PDEVICE_OBJECT gDeviceObject = nullptr;
extern UNICODE_STRING gDeviceName = RTL_CONSTANT_STRING(L"\\Device\\MemscanDriver");
extern UNICODE_STRING gDriverName = RTL_CONSTANT_STRING(L"\\Driver\\MemscanDriver");
extern UNICODE_STRING gSymLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\MemscanDriver");

// Whitelist of system processes
static const wchar_t* SystemProcessWhitelist[] = {
	// System processes
	L"\\SystemRoot\\System32\\csrss.exe",
	L"\\SystemRoot\\System32\\wininit.exe",
	L"\\SystemRoot\\System32\\services.exe",
	L"\\SystemRoot\\System32\\lsass.exe",

	// Edge processes
	L"\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
	L"\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\*\\msedgewebview2.exe",

	// Windows system processes
	L"\\Windows\\System32\\backgroundTaskHost.exe",
	L"\\Windows\\System32\\taskhostw.exe",
	L"\\Windows\\SystemApps\\Microsoft.Windows.Search_*\\SearchApp.exe",
	L"\\Windows\\SystemApps\\Microsoft.Windows.SecHealthUI_*\\SecHealthUI.exe",
	L"\\Windows\\System32\\SecurityHealthHost.exe",

	// VMware processes
	L"\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",

	// Frequently encountered processes
	L"\\Windows\\System32\\svchost.exe",
	L"\\Windows\\System32\\RuntimeBroker.exe",
	L"\\Windows\\System32\\dwm.exe",
	nullptr
};

//////////////////////////////// PRIVATE MICROSOFT STRUCTURES //////////////////////////////

typedef struct _ACTIVATION_CONTEXT _ACTIVATION_CONTEXT, * P_ACTIVATION_CONTEXT;
typedef struct _ACTIVATION_CONTEXT_DATA _ACTIVATION_CONTEXT_DATA, * P_ACTIVATION_CONTEXT_DATA;
typedef struct _ASSEMBLY_STORAGE_MAP _ASSEMBLY_STORAGE_MAP, * P_ASSEMBLY_STORAGE_MAP;
typedef struct _FLS_CALLBACK_INFO _FLS_CALLBACK_INFO, * P_FLS_CALLBACK_INFO;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	WORD Flags;
	WORD Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	PVOID Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	PVOID StandardInput;
	PVOID StandardOutput;
	PVOID StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;


typedef struct _PEB_LDR_DATA {
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		} TimeOrImports;
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef void* PPS_POST_PROCESS_INIT_ROUTINE;

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;