#pragma once

namespace utils
{
	uint64_t driver_pool_base;
	uint32_t driver_pool_size;

	/*
	* Gets a kernel module's base (ntoskrnl.exe, disk.sys, etc..).
	*/
	PVOID get_module_base(const char* module_name, size_t* size_output)
	{
		PVOID address = nullptr;
		ULONG size = 0;

		auto status = ZwQuerySystemInformation(SystemModuleInformation, &size, 0, &size);

		if (status != STATUS_INFO_LENGTH_MISMATCH)
		{
			return nullptr;
		}

		auto module_list = static_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePool(NonPagedPool, size));

		if (!module_list)
		{
			return nullptr;
		}

		status = ZwQuerySystemInformation(SystemModuleInformation, module_list, size, nullptr);

		if (!NT_SUCCESS(status))
		{
			ExFreePool(module_list);

			return address;
		}

		for (auto i = 0; i < module_list->ulModuleCount; i++)
		{
			auto module = module_list->Modules[i];
			if (strstr(module.ImageName, module_name))
			{
				address = module.Base;

				if (size_output != nullptr)
				{
					*size_output = module.Size;
				}

				break;
			}
		}

		ExFreePool(module_list);

		return address;
	}

	/*
	* Copies data to an allocated buffer.
	*/
	void* copy_to_buffer(void* src, uint32_t size)
	{
		auto buffer = reinterpret_cast<char*>(ExAllocatePool(NonPagedPool, size));

		if (buffer)
		{
			MM_COPY_ADDRESS address = { 0 };
			address.VirtualAddress = src;

			size_t read_data;

			if (NT_SUCCESS(MmCopyMemory(buffer, address, size, MM_COPY_MEMORY_VIRTUAL, &read_data)) && read_data == size)
			{
				return buffer;
			}

			ExFreePool(buffer);
		}
		else
		{
#ifdef DEBUG_MODE
			DbgPrintEx(0, 0, "could not allocate pool for buffer of size &d\n", size);
#endif
		}

		return nullptr;
	}

	/*
	* Finds a pattern of bytes in a given address range.
	*/
	template <typename t>
	t find_pattern(const char* pattern, const char* mask, void* start, size_t length)
	{
		const auto data = static_cast<const char*>(start);
		const auto pattern_length = strlen(mask);

		for (size_t i = 0; i <= length - pattern_length; i++)
		{
			bool found = true;

			for (size_t j = 0; j < pattern_length; j++)
			{
				if (!MmIsAddressValid(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(start) + i + j)))
				{
					found = false;
					break;
				}

				if (data[i + j] != pattern[j] && mask[j] != '?')
				{
					found = false;
					break;
				}
			}

			if (found)
			{
				return (t)(reinterpret_cast<uintptr_t>(start) + i);
			}
		}

		return (t)(nullptr);
	}

	/*
	* Walks the PEB and finds a process module's base address and size, and returns it.
	*/
	NTSTATUS get_process_module_base(PEPROCESS process, PUNICODE_STRING module_name, PVOID* module_address, ULONG* module_size)
	{
		if (process == nullptr)
		{
			return NULL;
		}
		
		PPEB process_peb = PsGetProcessPeb(process);

		if (!process_peb)
		{
			return STATUS_UNSUCCESSFUL;
		}

		PPEB_LDR_DATA peb_ldr = process_peb->Ldr;

		if (!peb_ldr)
		{
			return STATUS_UNSUCCESSFUL;
		}

		if (!peb_ldr->Initialized)
		{
			LARGE_INTEGER next_time;

			int retries = 0;

			while (!peb_ldr->Initialized && retries++ < 4)
			{
				next_time.QuadPart = -10000 * static_cast<long long>(250);
				KeDelayExecutionThread(KernelMode, FALSE, &next_time);
			}

			if (!peb_ldr->Initialized)
			{
				return STATUS_UNSUCCESSFUL;
			}
		}

		for (PLIST_ENTRY plist_entry = peb_ldr->InLoadOrderModuleList.Flink; plist_entry != &peb_ldr->InLoadOrderModuleList; plist_entry = plist_entry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY p_entry = CONTAINING_RECORD(plist_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (!RtlCompareUnicodeString(&p_entry->BaseDllName, module_name, TRUE))
			{
				if (module_address != nullptr)
				{
					*module_address = p_entry->DllBase;
				}

				if (module_size != nullptr)
				{
					*module_size = p_entry->SizeOfImage;
				}

				return STATUS_SUCCESS;
			}
		}
	}
}