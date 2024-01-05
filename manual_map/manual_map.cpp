#include "manual_map.hpp"

#include "../dll/dll.hpp"
#include "../util/process/process.hpp"

#include <array>

static void* map_module_base(HANDLE process, const rsh::dll& dll) {
	const auto optional_header = dll.headers().OptionalHeader;
	void* module_base = VirtualAllocEx(process, nullptr, optional_header.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (module_base == nullptr) {
		throw std::runtime_error("could not allocate module_base");
	}

	DWORD protection{};
	VirtualProtectEx(process, module_base, optional_header.SizeOfImage, PAGE_EXECUTE_READWRITE, &protection);

	if (WriteProcessMemory(process, module_base, dll.data().data(), 0x1000, nullptr) == false) {
		VirtualFreeEx(process, module_base, 0, MEM_RELEASE);

		throw std::runtime_error(std::format("could not load file header 0x{:x}", GetLastError()));
	}

	return module_base;
}

static void map_module_sections(HANDLE process, void* module_base, const rsh::dll& dll, const injection::manual_map_options& options) {
	for (const auto& section : dll.sections()) {
		const auto location = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(module_base) + section.VirtualAddress);

		if (section.SizeOfRawData != 0 && WriteProcessMemory(process, location, dll.data().data() + section.PointerToRawData, section.SizeOfRawData, nullptr) == false) {
			VirtualFreeEx(process, module_base, 0, MEM_RELEASE);

			throw std::runtime_error(std::format("could not map sections 0x{:x}", GetLastError()));
		}

		if (const auto virtual_size = section.Misc.VirtualSize) {
			if (options.remove_extra_sections) {
				const std::string_view& section_name = reinterpret_cast<const char*>(section.Name);

				if (section_name == ".pdata" || section_name == ".rsrc" || section_name == ".reloc") {
					std::vector<std::uint8_t> empty_buffer{};
					empty_buffer.reserve(virtual_size);

					WriteProcessMemory(process, location, empty_buffer.data(), empty_buffer.size(), nullptr);
				}
			}

			if (options.adjust_protections) {
				const auto protection = [&]() -> DWORD {
					if ((section.Characteristics & IMAGE_SCN_MEM_WRITE) >= 0) {
						return PAGE_EXECUTE_READWRITE;
					} else if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) >= 0) {
						return PAGE_EXECUTE_READ;
					}

					return PAGE_READONLY;
				}();

				DWORD old_protection{};

				VirtualProtectEx(process, location, virtual_size, protection, &old_protection);
			}
		}
	}
}

struct invoke_context {
public:
	using load_library_t = HMODULE(__stdcall*)(LPCSTR);
	using get_proc_address_t = FARPROC(__stdcall*)(HMODULE, LPCSTR);
public:
	load_library_t load_library_a;
	get_proc_address_t get_proc_address;
	void* module_base;
	void* reserved;
};

static void* map_invoke_context(HANDLE process, void* module_base, void* reserved = nullptr) {
	invoke_context context_instance{
		.load_library_a = LoadLibraryA,
		.get_proc_address = GetProcAddress,
		.module_base = module_base,
		.reserved = reserved
	};

	void* context = VirtualAllocEx(process, nullptr, sizeof(invoke_context), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!context) {
		VirtualFreeEx(process, module_base, 0, MEM_RELEASE);

		throw std::runtime_error(std::format("could not create invoke context 0x{:x}", GetLastError()));
	}

	if (!WriteProcessMemory(process, context, &context_instance, sizeof(invoke_context), nullptr)) {
		VirtualFreeEx(process, module_base, 0, MEM_RELEASE);
		VirtualFreeEx(process, context, 0, MEM_RELEASE);

		throw std::runtime_error(std::format("could not load invoke context 0x{:x}", GetLastError()));
	}

	return context;
}

static void relocate_image(void* module_base, const IMAGE_DATA_DIRECTORY& data_directory, std::uintptr_t new_relative_location) {
	const auto& module_base_ptr = reinterpret_cast<std::uintptr_t>(module_base);
	auto relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(module_base_ptr + data_directory.VirtualAddress);

	while (relocation->VirtualAddress) {
		std::size_t entries = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		auto relocation_type = reinterpret_cast<WORD*>(reinterpret_cast<std::uintptr_t>(relocation) + 1);

		for (std::size_t i{}; i != entries; ++i, ++relocation_type) {
			if ((*relocation_type >> 0x0C) == IMAGE_REL_BASED_HIGHLOW) {
				*reinterpret_cast<std::uintptr_t*>(module_base_ptr + relocation->VirtualAddress + (*relocation_type & 0xfff)) += new_relative_location;
			}
		}

		relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<std::uintptr_t>(relocation) + relocation->SizeOfBlock);
	}
}

static void realign_imports(void* module_base, const IMAGE_DATA_DIRECTORY& data_directory, invoke_context& context) {
	const auto module_base_ptr = reinterpret_cast<std::uintptr_t>(module_base);
	
	for (auto import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(module_base_ptr + data_directory.VirtualAddress);
		import_descriptor->Name; ++import_descriptor
	) {
		const auto module_name = reinterpret_cast<char*>(module_base_ptr + import_descriptor->Name);
		const auto module_handle = context.load_library_a(module_name);

		auto thunk = reinterpret_cast<std::uintptr_t*>(module_base_ptr + import_descriptor->OriginalFirstThunk);
		auto function = reinterpret_cast<std::uintptr_t*>(module_base_ptr + import_descriptor->FirstThunk);

		if (thunk == nullptr) {
			thunk = function;
		}

		for (; *thunk; ++thunk, ++function) {
			if (IMAGE_SNAP_BY_ORDINAL(*thunk)) {
				*function = reinterpret_cast<std::uintptr_t>(context.get_proc_address(module_handle, module_name));
			} else {
				auto named_import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(module_base_ptr + *thunk);
				*function = reinterpret_cast<std::uintptr_t>(context.get_proc_address(module_handle, named_import->Name));
			}
		}
	}
}

static void invoke_tls_callbacks(void* module_base, const IMAGE_DATA_DIRECTORY& data_directory) {
	auto tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(reinterpret_cast<std::uintptr_t>(module_base) + data_directory.VirtualAddress);

	for (auto current_callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks); 
		current_callback && *current_callback; ++current_callback
	) {
		(*current_callback)(module_base, DLL_PROCESS_ATTACH, nullptr);
	}
}

static void __stdcall invoke_entry(invoke_context& context) {
	void*& module_base = context.module_base;

	const auto& module_base_ptr = reinterpret_cast<std::uintptr_t>(module_base);
	const auto& file_address = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base)->e_lfanew;
	const auto& optional_header = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base_ptr + file_address)->OptionalHeader;
	const auto dll_main = reinterpret_cast<bool(__stdcall*)(HMODULE, DWORD, void*)>(module_base_ptr + optional_header.AddressOfEntryPoint);

	if (const auto& data_directory = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		module_base_ptr - optional_header.ImageBase != 0 && data_directory.Size != 0
	) {
		relocate_image(module_base, data_directory, module_base_ptr - optional_header.ImageBase);
	}

	if (const auto& data_directory = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		data_directory.Size != 0
	) {
		realign_imports(module_base, data_directory, context);
	}

	if (const auto& data_directory = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		data_directory.Size != 0
	) {
		invoke_tls_callbacks(module_base, data_directory);
	}

	dll_main(reinterpret_cast<HMODULE>(module_base), DLL_PROCESS_ATTACH, context.reserved);
}

static void* map_entry_caller(HANDLE process, void* module_base, void* context) {
	void* entry_caller = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (entry_caller == nullptr) {
		VirtualFreeEx(process, module_base, 0, MEM_RELEASE);
		VirtualFreeEx(process, context, 0, MEM_RELEASE);

		throw std::runtime_error(std::format("could not create entry caller 0x{:x}", GetLastError()));
	}

	if (WriteProcessMemory(process, entry_caller, invoke_entry, 0x1000, nullptr) == false) {
		VirtualFreeEx(process, module_base, 0, MEM_RELEASE);
		VirtualFreeEx(process, context, 0, MEM_RELEASE);
		VirtualFreeEx(process, entry_caller, 0, MEM_RELEASE);

		throw std::runtime_error(std::format("could not load entry caller 0x{:x}", GetLastError()));
	}

	return entry_caller;
}

static void exec_entry_caller(HANDLE process, void* entry_caller, void* context, void* module_base) {
	HANDLE thread = CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(entry_caller), context, 0, nullptr);

	if (thread == nullptr) {
		VirtualFreeEx(process, module_base, 0, MEM_RELEASE);
		VirtualFreeEx(process, context, 0, MEM_RELEASE);
		VirtualFreeEx(process, entry_caller, 0, MEM_RELEASE);

		throw std::runtime_error(std::format("could not execute entry caller 0x{:x}", GetLastError()));
	}

	CloseHandle(thread);
}

namespace injection {
	void manual_map(const std::filesystem::path& dll_path, const std::wstring_view& process_name, const manual_map_options& options) {
		const rsh::dll dll{ dll_path };
		const HANDLE process = util::process::find(process_name);

		if (process == nullptr) {
			throw std::runtime_error(std::format(R"(could not find "{}")", std::string(process_name.begin(), process_name.end())));
		}

		void* module_base = map_module_base(process, dll);
		void* context = map_invoke_context(process, module_base, options.reserved);
		void* entry_caller = map_entry_caller(process, module_base, context);

		map_module_sections(process, module_base, dll, options);

		if (options.exclude_headers) {
			std::array<std::uint8_t, 0x1000> empty_buffer{};

			WriteProcessMemory(process, module_base, empty_buffer.data(), empty_buffer.size(), nullptr);
		}

		exec_entry_caller(process, entry_caller, context, module_base);
	}
}
