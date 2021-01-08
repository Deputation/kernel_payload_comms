#include "kdmapper.hpp"

/*
* This should always be called before performing operations on the shared memory's structure(s)
* to serialize access and make sure we do not overwrite data while it is being used by the kernel payload,
* resulting in undefined behavior.
*/
void kdmapper::comms::wait_for_op_to_end()
{
	using namespace std::chrono_literals;

	while (shared_memory.operation != op_complete)
	{
		std::this_thread::sleep_for(1ns);
	}
}


bool kdmapper::comms::is_address_valid(uint64_t address)
{
	return address && address < 0x7FFFFFFEFFFF;
}

/*
* ping!
*/
void kdmapper::comms::ping()
{
	wait_for_op_to_end();

	shared_memory.operation = op_ping;
}

void kdmapper::comms::unload_payload()
{
	wait_for_op_to_end();

	shared_memory.operation = op_unload;
}

void kdmapper::comms::mm_copy_virtual_memory(uint32_t source_pid, uint64_t source_address, uint32_t target_pid, 
	uint64_t target_address, size_t operation_size)
{
	if (is_address_valid(source_address) && is_address_valid(target_address))
	{
		wait_for_op_to_end();

		shared_memory.memory_operation_params.source_pid = source_pid;
		shared_memory.memory_operation_params.source_address = source_address;
		shared_memory.memory_operation_params.target_pid = target_pid;
		shared_memory.memory_operation_params.target_address = target_address;
		shared_memory.memory_operation_params.size = operation_size;
		/*
		* as soon as we set this, the driver will be reading everything and executing the operation.
		*/
		shared_memory.operation = op_memory;

		/*
		* all reading / writing operations should not return before the operation is done to ensure data consistency.
		*/
		wait_for_op_to_end();
	}
}

uint64_t kdmapper::map_driver(HANDLE iqvw64e_device_handle, const std::string& driver_path)
{
	std::vector<uint8_t> raw_image = { 0 };

	if (!utils::read_file_to_memory(driver_path, &raw_image))
	{
		std::cout << "[-] Failed to read image to memory" << std::endl;
		return 0;
	}

	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::get_nt_headers(raw_image.data());

	if (!nt_headers)
	{
		std::cout << "[-] Invalid format of PE image" << std::endl;
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		std::cout << "[-] Image is not 64 bit" << std::endl;
		return 0;
	}

	const uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;

	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	uint64_t kernel_image_base = intel_driver::allocate_pool(iqvw64e_device_handle, nt::NonPagedPool, image_size);

	do
	{
		if (!kernel_image_base)
		{
			std::cout << "[-] Failed to allocate remote image in kernel" << std::endl;
			break;
		}

		std::cout << "[+] Image base has been allocated at 0x" << reinterpret_cast<void*>(kernel_image_base) << std::endl;

		// Copy image headers

		memcpy(local_image_base, raw_image.data(), nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
		{
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(local_image_base) + current_image_section[i].VirtualAddress);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(raw_image.data()) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
		}

		// Resolve relocs and imports

		relocate_image_by_delta(portable_executable::get_relocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		if (!resolve_imports(iqvw64e_device_handle, portable_executable::get_imports(local_image_base)))
		{
			std::cout << "[-] Failed to resolve imports" << std::endl;
			break;
		}

		// Write fixed image to kernel

		if (!intel_driver::write_memory(iqvw64e_device_handle, kernel_image_base, local_image_base, image_size))
		{
			std::cout << "[-] Failed to write local image to remote image" << std::endl;
			break;
		}

		VirtualFree(local_image_base, 0, MEM_RELEASE);

		/*
		* Calculate entry point address.
		*/
		const uint64_t address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		std::cout << "[<] Calling DriverEntry 0x" << reinterpret_cast<void*>(address_of_entry_point) << std::endl;

		NTSTATUS status = 0;

		memset((void*)(&kdmapper::comms::shared_memory), 0, sizeof(kdmapper::comms::mapped_memory));
		comms::shared_memory.operation = kdmapper::comms::op_complete;

		/*
		* Call our custom entry point with all the parameters that we need to pass to it to ensure communication
		* is successful.
		*/
		if (!intel_driver::call_kernel_function(iqvw64e_device_handle, &status, address_of_entry_point, 
			kernel_image_base, image_size, GetCurrentProcessId(), reinterpret_cast<uint64_t>(&comms::shared_memory)))
		{
			std::cout << "[-] Failed to call driver entry" << std::endl;
			break;
		}

		std::cout << "[+] DriverEntry returned 0x" << std::hex << std::setw(8) << std::setfill('0') << std::uppercase << status << std::nouppercase << std::dec << std::endl;

		/*
		* Making it harder for pool scanners to be able to understand that the pool they found is, in fact,
		* a pool containing a mapped driver; it is in fact quite easy to look for a set amount of zeros consecutively
		* in memory and come to the conclusion that the pool you're currently reading is a mapped driver because of the
		* zeroed out PE header, which has a set size. Randomizing it fixes the issue. Kdmapper, instead, by default, 
		* sets it to zero.
		*/
		for (auto i = 0; i < nt_headers->OptionalHeader.SizeOfHeaders; i++)
		{
			uint8_t random = __rdtsc() % 0xff;

			intel_driver::write_memory(iqvw64e_device_handle, kernel_image_base + i, &random, 1);
		}

		std::cout << "[+] Randomized PE headers" << std::endl;

		return kernel_image_base;

	} while (false);

	VirtualFree(local_image_base, 0, MEM_RELEASE);
	intel_driver::free_pool(iqvw64e_device_handle, kernel_image_base);

	return 0;
}

void kdmapper::relocate_image_by_delta(portable_executable::vec_relocs relocs, const uint64_t delta)
{
	for (const auto& current_reloc : relocs)
	{
		for (auto i = 0u; i < current_reloc.count; ++i)
		{
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				* reinterpret_cast<uint64_t*>(current_reloc.address + offset) += delta;
		}
	}
}

bool kdmapper::resolve_imports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports)
{
	for (const auto& current_import : imports)
	{
		if (!utils::get_kernel_module_address(current_import.module_name))
		{
			std::cout << "[-] Dependency " << current_import.module_name << " wasn't found" << std::endl;
			return false;
		}

		for (auto& current_function_data : current_import.function_datas)
		{
			const uint64_t function_address = intel_driver::get_kernel_module_export(iqvw64e_device_handle, utils::get_kernel_module_address(current_import.module_name), current_function_data.name);

			if (!function_address)
			{
				std::cout << "[-] Failed to resolve import " << current_function_data.name << " (" << current_import.module_name << ")" << std::endl;
				return false;
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}
