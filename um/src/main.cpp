#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>

#define IOCTL_ATTACH_PROCESS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_MEMORY      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_IOC_BUFFER   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x699, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_IOC_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x69A, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IOC (Indicators of Compromise) buffer constants
#define IOC_MAX_ENTRIES    512
#define IOC_MESSAGE_SIZE   128

/**
 * @brief Commands supported by the utility
 */
enum class CommandType {
	Attach,
	Read,
	Write,
	GetIoc,
	ClearIoc,
	Invalid
};

/**
 * @brief Gets ID of a given running process
 * @param process_name Name of a running process (wide)
 * @return PID or 0 if not found
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
		constexpr ULONG attach = IOCTL_ATTACH_PROCESS;		// Setup the driver
		constexpr ULONG read = IOCTL_READ_MEMORY;			// Read process memory
		constexpr ULONG write = IOCTL_WRITE_MEMORY;			// Write process memory
		constexpr ULONG get_ioc = IOCTL_GET_IOC_BUFFER;		// Copy ioc to um
		constexpr ULONG clear_ioc = IOCTL_CLEAR_IOC_BUFFER;	// Clear ioc buffer and counter 

	} //namespace codes

	// Shared between um & km
	struct Request {
		HANDLE ProcessId;

		PVOID pTarget;
		PVOID pBuffer;

		SIZE_T BufferSize;
		SIZE_T ReturnSize;
	};

	/**
	 * @brief Attach driver to a process
	 * @param DriverHandle
	 * @param pid
	 * @return
	 */
	bool AttachToProcess(HANDLE DriverHandle, const DWORD pid) {
		Request request;
		request.ProcessId = reinterpret_cast<HANDLE>(pid);

		return DeviceIoControl(DriverHandle, codes::attach, &request,
			sizeof(request), &request, sizeof(request),
			nullptr, nullptr);
	}

	/**
	 * @brief Read memory of type T from target process
	 * @tparam T Memory type
	 * @param DriverHandle
	 * @param target_address
	 * @param buffer
	 * @return
	 */
	template <class T>
	bool ReadMemory(HANDLE DriverHandle, const std::uintptr_t target_address, T& buffer) {
		Request request;
		request.pTarget = reinterpret_cast<PVOID>(target_address);
		request.pBuffer = &buffer;
		request.BufferSize = sizeof(T);

		return DeviceIoControl(DriverHandle, codes::read, &request,
							   sizeof(request), &request, sizeof(request),
							   nullptr, nullptr);
	}

	/**
	 * @brief Write a value to given memory
	 * @tparam T 
	 * @param DriverHandle 
	 * @param target_address 
	 * @param value 
	 * @return 
	 */
	template <class T>
	bool WriteMemory(HANDLE DriverHandle, const std::uintptr_t target_address, const T& value) {
		Request request;
		request.pTarget = reinterpret_cast<PVOID>(target_address);
		request.pBuffer = (PVOID)&value;
		request.BufferSize = sizeof(T);

		return DeviceIoControl(DriverHandle, codes::write, &request,
							   sizeof(request), &request, sizeof(request),
							   nullptr, nullptr);
	}

	/**
	 * @brief Retrieve IOC log entries
	 * @param DriverHandle 
	 * @return 
	 */
	std::vector<std::string> GetIocBuffer(HANDLE DriverHandle) {
		std::vector<char> raw(IOC_MAX_ENTRIES * IOC_MESSAGE_SIZE);
		DWORD bytes_returned;

		if (!DeviceIoControl(DriverHandle, codes::get_ioc, nullptr,
							 0, raw.data(), static_cast<DWORD>(raw.size()),
							 &bytes_returned, nullptr)) {
			return {};
		}

		std::vector<std::string> entries;
		size_t count = bytes_returned / IOC_MESSAGE_SIZE;

		for (size_t i = 0; i < count; ++i) {
			entries.emplace_back(raw.data() + i * IOC_MESSAGE_SIZE);
		}
		
		return entries;
	}

	/**
	 * @brief Clear IOC log buffer
	 * @param DriverHandle 
	 */
	bool ClearIocBuffer(HANDLE DriverHandle) {
		return DeviceIoControl(DriverHandle, codes::clear_ioc, nullptr, 0, nullptr, 0, nullptr, nullptr);
	}

} // namespace driver

/**
 * @brief Print usage
 */
void PrintUsage() {
	std::cout << "Usage:\n"
		<< "  memscan attach <pid|name>\n"
		<< "  memscan read <pid|name> <address> <length>\n"
		<< "  memscan write <pid|name> <address> <hex bytes...>\n"
		<< "  memscan get_ioc\n"
		<< "  memscan clear_ioc\n";
}

/**
 * @brief Parse pid or process name
 * @param arg 
 * @return 
 */
static DWORD ParsePid(const char* arg) {
	// If all digits, treat as PID; otherwise, as process name
	bool isNum = true;
	for (const char* p = arg; *p; ++p) {
		if (!isdigit(*p)) { isNum = false; break; }
	}
	if (isNum) {
		return std::stoul(arg);
	}
	else {
		// Convert to wide and strip quotes if any
		std::wstring wname;
		int len = MultiByteToWideChar(CP_UTF8, 0, arg, -1, nullptr, 0);
		wname.resize(len);
		MultiByteToWideChar(CP_UTF8, 0, arg, -1, &wname[0], len);
		return GetProcessId(wname.c_str());
	}
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		PrintUsage();
		std::cin.get();
		return 1;
	}
	std::string cmd = argv[1];
	CommandType type = CommandType::Invalid;
	if (cmd == "attach")       type = CommandType::Attach;
	else if (cmd == "read")    type = CommandType::Read;
	else if (cmd == "write")   type = CommandType::Write;
	else if (cmd == "get_ioc") type = CommandType::GetIoc;
	else if (cmd == "clear_ioc") type = CommandType::ClearIoc;

	const HANDLE driver = CreateFile(L"\\\\.\\MemscanDriver", GENERIC_READ, 0, nullptr, 
									 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (driver == INVALID_HANDLE_VALUE) {
		std::cout << "[-] Failed to create driver handle.\n";
		std::cin.get();
		return 1;
	}

	bool status = false;
	switch (type) {
		case CommandType::Attach: {
			if (argc == 3) {
				DWORD pid = ParsePid(argv[2]);
				status = driver::AttachToProcess(driver, pid);
				if (!status) {
					std::cerr << "[-] Failed to attach to process " << pid << " (IOCTL error).\n";
				}
				else {
					std::cout << "[+] Attached to process " << pid << "\n";
				}
			}
			break;
		}
		
		case CommandType::Read: {
			if (argc == 5) {
				DWORD pid = ParsePid(argv[2]);
				std::uintptr_t addr = std::stoull(argv[3], nullptr, 16);
				size_t width = std::stoul(argv[4]);
				
				if (driver::AttachToProcess(driver, pid)) {
					switch (width) {
						case 1: {
							uint8_t value8;
							status = driver::ReadMemory<uint8_t>(driver, addr, value8);
							if (status) std::cout << "[+] Read value (1 bytes): " << value8 << "\n";
							else std::cerr << "[-] Failed to read value (1 bytes).\n";
						}
						case 2: {
							uint16_t value16;
							status = driver::ReadMemory<uint16_t>(driver, addr, value16);
							if (status) std::cout << "[+] Read value (2 bytes): " << value16 << "\n";
							else std::cerr << "[-] Failed to read value (2 bytes).\n";
							break;
						}
						case 4: {
							uint32_t value32;
							status = driver::ReadMemory<uint32_t>(driver, addr, value32);
							if (status) std::cout << "[+] Read value (4 bytes): " << value32 << "\n";
							else std::cerr << "[-] Failed to read value (4 bytes).\n";
							break;
						}
						case 8: {
							uint64_t value64;
							status = driver::ReadMemory<uint64_t>(driver, addr, value64);
							if (status) std::cout << "[+] Read value (8 bytes): " << value64 << "\n";
							else std::cerr << "[-] Failed to read value (8 bytes).\n";
							break;
						}
						default:
							std::cerr << "[-] Unsupported width: " << width << ". Only 1,2,4,8 supported.\n";
							break;
						}
				}
			}
			break;
		}
	
		case CommandType::Write: {
			if (argc == 5) {
				DWORD pid = ParsePid(argv[2]);
				std::uintptr_t addr = std::stoull(argv[3], nullptr, 16);
				size_t width = std::stoul(argv[4]);
				std::cout << "Enter value (hex): ";
				switch (width) {
					case 1: {
						uint32_t temp;
						std::cin >> std::hex >> temp;
						uint8_t value8 = static_cast<uint8_t>(temp);
						if (driver::AttachToProcess(driver, pid)) {
							status = driver::WriteMemory<uint8_t>(driver, addr, value8);
							if (status) std::cout << "[+] Wrote 1 byte value.\n";
							else std::cerr << "[-] Failed to write 1 byte value.\n";
						}
						break;
					}
					case 2: {
						uint16_t value16;
						std::cin >> std::hex >> value16;
						if (driver::AttachToProcess(driver, pid)) {
							status = driver::WriteMemory<uint16_t>(driver, addr, value16);
							if (status) std::cout << "[+] Wrote 2 byte value.\n";
							else std::cerr << "[-] Failed to write 2 byte value.\n";
						}
						break;
					}
					case 4: {
						uint32_t value32;
						std::cin >> std::hex >> value32;
						if (driver::AttachToProcess(driver, pid)) {
							status = driver::WriteMemory<uint32_t>(driver, addr, value32);
							if (status) std::cout << "[+] Wrote 4 byte value.\n";
							else std::cerr << "[-] Failed to write 4 byte value.\n";
						}
						break;
					}
					case 8: {
						uint64_t value64;
						std::cin >> std::hex >> value64;
						if (driver::AttachToProcess(driver, pid)) {
							status = driver::WriteMemory<uint64_t>(driver, addr, value64);
							if (status) std::cout << "[+] Wrote 8 byte value.\n";
							else std::cerr << "[-] Failed to write 8 byte value.\n";
						}
						break;
					}
					default:
						std::cerr << "[-] Unsupported width: " << width << ". Only 1,2,4,8 supported.\n";
						break;
				}
			}
			break;
		}
	
		case CommandType::GetIoc: {
			auto logs = driver::GetIocBuffer(driver);
			if (logs.empty()) {
				std::cerr << "[-] Failed to get IOC logs from driver.\n";
				status = false;
				break;
			}
			for (const auto& l : logs) std::cout << l << "\n";
			status = true;
			break;
		}

		case CommandType::ClearIoc: {
			status = driver::ClearIocBuffer(driver);
			if (!status) {
				std::cerr << "[-] Failed to clear IOC logs.\n";
			}
			break;
		}

		default: {
			PrintUsage();
			break;
		}
	}

	CloseHandle(driver);

	std::cin.get();

	return 0;
}