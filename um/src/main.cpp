#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

/**
 * @brief Gets ID of a given running process
 * @param process_name Name of a running process
 * @return Process ID of a given running process
 */
static DWORD GetProcessId(const wchar_t* process_name) {
	DWORD process_id = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return process_id;
	}

	PROCESSENTRY32W entry = {};
	entry.dwSize = sizeof(decltype(entry));

	if (Process32FirstW(snapshot, &entry) == TRUE) {
		if (_wcsicmp(process_name, entry.szExeFile) == 0) {
			process_id = entry.th32ProcessID;
		}
		else {
			while (Process32NextW(snapshot, &entry) == TRUE) {
				if (_wcsicmp(process_name, entry.szExeFile) == 0) {
					process_id = entry.th32ProcessID;
				}
			}
		}
	}

	CloseHandle(snapshot);

	return process_id;
}

/**
 * @brief Gets an address of a given module in given process
 * @param pid Process ID of a process to find module in
 * @param module_name Name of a module to find in process memory
 * @return Pointer to a module base or nullptr
 */
static std::uintptr_t GetModuleBase(const DWORD pid, const wchar_t* module_name) {
	std::uintptr_t module_base = 0;
	
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return module_base;
	}

	MODULEENTRY32W entry = {};
	entry.dwSize = sizeof(decltype(entry));

	if (Module32FirstW(snapshot, &entry) == TRUE) {
		if (wcsstr(module_name, entry.szModule) != nullptr) {
			module_base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
		}
		else {
			while (Module32NextW(snapshot, &entry) == TRUE) {
				if (wcsstr(module_name, entry.szModule) != nullptr) {
					module_base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
				}
			}
		}
	}

	CloseHandle(snapshot);

	return module_base;
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

	bool AttachToProcess(HANDLE DriverHandle, const DWORD pid) {
		Request request;
		request.ProcessId = reinterpret_cast<HANDLE>(pid);

		return DeviceIoControl(DriverHandle, codes::attach, &request,
							   sizeof(request), &request, sizeof(request),
							   nullptr, nullptr);
	}

	template <class T>
	T ReadMemory(HANDLE DriverHandle, const std::uintptr_t target_address) {
		T temp = {};

		Request request;
		request.pTarget = reinterpret_cast<PVOID>(target_address);
		request.pBuffer = &temp;
		request.BufferSize = sizeof(T);

		DeviceIoControl(DriverHandle, codes::read, &request,
			sizeof(request), &request, sizeof(request),
			nullptr, nullptr);

		return temp;
	}

	template <class T>
	void WriteMemory(HANDLE DriverHandle, const std::uintptr_t target_address, const T& value) {
		Request request;
		request.pTarget = reinterpret_cast<PVOID>(target_address);
		request.pBuffer = (PVOID)&value;
		request.BufferSize = sizeof(T);

		DeviceIoControl(DriverHandle, codes::write, &request,
			sizeof(request), &request, sizeof(request),
			nullptr, nullptr);
	}

} // namespace driver

int main() {
	const DWORD pid = GetProcessId(L"notepad.exe");

	if (pid == 0) {
		std::cout << "[-] Failed to get process.\n";
		std::cin.get();
		return 1;
	}

	const HANDLE driver = CreateFile(L"\\\\.\\MemscanDriver", GENERIC_READ, 0, nullptr, 
									 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (driver == INVALID_HANDLE_VALUE) {
		std::cout << "[-] Failed to create driver handle.\n";
		std::cin.get();
		return 1;
	}

	if (driver::AttachToProcess(driver, pid) == true) {
		std::cout << "[+] Attachment success.\n";
	}

	CloseHandle(driver);

	std::cin.get();

	return 0;
}