#pragma once
#include <Windows.h>
#include <stdint.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <filesystem>

#include "portable_executable.hpp"
#include "utils.hpp"
#include "nt.hpp"
#include "intel_driver.hpp"

namespace kdmapper
{
	namespace comms
	{
		/*
		* Valid shared memory operation states.
		*/
		enum e_operation
		{
			op_ping,
			op_memory,
			op_complete,
			op_unload,
			op_ready
		};

		/*
		* Structure to lay out in memory the parameters of MmCopyVirtualMemory.
		*/
		struct mm_copy_vm_params
		{
			uint32_t source_pid;
			uint64_t source_address;
			uint32_t target_pid;
			uint64_t target_address;
			size_t size;
		};

		/*
		* The structure of the shared memory.
		*/
		struct mapped_memory
		{
			uint32_t operation;
			mm_copy_vm_params memory_operation_params;
		};

		/*
		* We should define variables that are modified externally (memory-wise) as volatile.
		*/
		inline volatile mapped_memory shared_memory;

		/*
		* This should always be called before performing operations on the shared memory's structure(s)
		* to serialize access and make sure we do not overwrite data while it is being used by the kernel payload,
		* resulting in undefined behavior.
		*/
		void wait_for_op_to_end();

		/*
		* Kernel addresses manipulation should be done straight from the kernel payload for
		* performance and safety reasons.
		*/
		bool is_address_valid(uint64_t address);

		/*
		* ping!
		*/
		void ping();

		/*
		* Unload the kernel payload (it will simply jmp to ExFreePool)
		*/
		void unload_payload();
		
		/*
		* Send to the kernel payload the parameters you want to call MmCopyVirtualMemory with.
		*/
		void mm_copy_virtual_memory(uint32_t source_pid, uint64_t source_address, uint32_t target_pid, uint64_t target_address, 
			size_t operation_size);

		/*
		* Simple wrapper to to use MmCopyVirtualMemory to read virtual memory.
		*/
		template <typename T>
		inline T read_vm(uint32_t pid, uint64_t address)
		{
			T buffer;

			memset(&buffer, 0, sizeof(T));

			mm_copy_virtual_memory(pid, address, GetCurrentProcessId(), reinterpret_cast<uint64_t>(&buffer), sizeof(T));

			return buffer;
		}

		/*
		* Simple wrapper to use MmCopyVirtualMemory to write to virtual memory.
		*/
		template <typename T>
		inline void write_vm(uint32_t pid, uint64_t address, T value)
		{
			T buffer = value;

			mm_copy_virtual_memory(GetCurrentProcessId(), reinterpret_cast<uint64_t>(&buffer), pid, address, sizeof(T));
		}
	}

	uint64_t map_driver(HANDLE iqvw64e_device_handle, const std::string& driver_path);
	void relocate_image_by_delta(portable_executable::vec_relocs relocs, const uint64_t delta);
	bool resolve_imports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports);
}