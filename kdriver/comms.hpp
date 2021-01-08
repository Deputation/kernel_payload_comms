#pragma once

namespace comms
{
	/*
	* Data vital to payload communication and setup.
	*/
	PEPROCESS client_peprocess;
	uint32_t client_pid;
	uint64_t shared_memory_address;

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
	* Variable holding a pointer to the mapped memory structure.
	*/
	mapped_memory* remapped_memory;

	/*
	* pong!
	*/
	bool handle_ping()
	{
#ifdef DEBUG_MODE
		DbgPrintEx(0, 0, "pong!\n");
#endif
		return true;
	}

	/*
	* Call MmCopyVirtualMemory with the parameters coming from usermode.
	*/
	bool handle_memory()
	{
		PEPROCESS source_process, target_process;

		if (NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(remapped_memory->memory_operation_params.source_pid), &source_process)) &&
			NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(remapped_memory->memory_operation_params.target_pid), &target_process)))
		{
			/*
			* Simple and naive memory address validation, simple checks like whether or not the address is in a 
			* usermode address range will be done from the usermode wrapper.
			*/

			KAPC_STATE apc_state;
			KeStackAttachProcess(source_process, &apc_state);
			auto source_valid = MmIsAddressValid(reinterpret_cast<PVOID>(remapped_memory->memory_operation_params.source_address));
			KeUnstackDetachProcess(&apc_state);

			KeStackAttachProcess(target_process, &apc_state);
			auto target_valid = MmIsAddressValid(reinterpret_cast<PVOID>(remapped_memory->memory_operation_params.target_address));
			KeUnstackDetachProcess(&apc_state);

			SIZE_T bytes_elaborated;

			if (source_valid && target_valid)
			{
				MmCopyVirtualMemory(source_process, reinterpret_cast<PVOID>(remapped_memory->memory_operation_params.source_address),
					target_process, reinterpret_cast<PVOID>(remapped_memory->memory_operation_params.target_address),
					remapped_memory->memory_operation_params.size, KernelMode, &bytes_elaborated);
			}

			ObDereferenceObject(source_process);
			ObDereferenceObject(target_process);
		}

		return true;
	}

	/*
	* Simple loop that handles all the different states of the mapped memory structure.
	* Returning false will result in the payload's self destruction.
	*/
	bool loop()
	{
		auto result = false;

		if (remapped_memory->operation != op_complete)
		{
			switch (remapped_memory->operation)
			{
			case op_memory:
				result = handle_memory();
				break;
			case op_ping:
				result = handle_ping();
				break;
			case op_unload:
				result = false;
				break;
			}

			remapped_memory->operation = op_complete;
		}
		else
		{
			result = true;
		}

		return result;
	}
}