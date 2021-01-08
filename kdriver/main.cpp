#include "common.hpp"

VOID thread_entry(PVOID context)
{
	/*
	* Get the client's PEPROCESS, it is vital to continue the execution.
	*/
	if (NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(comms::client_pid), &comms::client_peprocess)))
	{
#ifdef DEBUG_MODE
		DbgPrintEx(0, 0, "gathered client_peprocess\n");
#endif
		
		/*
		* Attach to the process to get the shared memory structure's physical address to map it.
		*/
		KAPC_STATE apc_state;
		KeStackAttachProcess(comms::client_peprocess, &apc_state);
		{
			/*
			* Gather the physical address.
			*/
			auto shared_memory_physical = MmGetPhysicalAddress(reinterpret_cast<PVOID>(comms::shared_memory_address));
			
#ifdef DEBUG_MODE
			DbgPrintEx(0, 0, "shared memory physical address %p\n", shared_memory_physical);
#endif

			if (shared_memory_physical.QuadPart)
			{
				/*
				* If we got a physical address, we can now map it and save it, we now have access to the same structure
				* the usermode client has access to, and communication can now start.
				*/
				comms::remapped_memory = 
					reinterpret_cast<comms::mapped_memory*>(MmMapIoSpace(shared_memory_physical, sizeof(comms::mapped_memory),
					MmNonCached));

				if (comms::remapped_memory)
				{
#ifdef DEBUG_MODE
					DbgPrintEx(0, 0, "mapped physical address at %p\n", comms::remapped_memory);
#endif
				}
			}
		}
		KeUnstackDetachProcess(&apc_state);

		if (comms::remapped_memory)
		{
			while (true)
			{
				if (!comms::loop())
				{
					break;
				}
			}
		}

		ObDereferenceObject(comms::client_peprocess);
	}
	else
	{
#ifdef DEBUG_MODE
		DbgPrintEx(0, 0, "couldn't gather client's peprocess...\n");
#endif
	}

#ifdef DEBUG_MODE
	DbgPrintEx(0, 0, "preparing to self destruct...\n");
#endif

	if (comms::remapped_memory)
	{
		MmUnmapIoSpace(reinterpret_cast<PVOID>(comms::remapped_memory), sizeof(comms::mapped_memory));
	}

	jmp_to_ex_free_pool(reinterpret_cast<void*>(utils::driver_pool_base));
}

extern "C" NTSTATUS driver_main(uint64_t pool_base, uint32_t pool_size, uint32_t client_pid, uint64_t shared_memory_address)
{
	/*
	* Save all the data for initialization and communication purposes (utils::driver_pool_size will stay unused for now).
	*/
	utils::driver_pool_base = pool_base;
	utils::driver_pool_size = pool_size;
	comms::client_pid = client_pid;
	comms::shared_memory_address = shared_memory_address;

#ifdef DEBUG_MODE
	DbgPrintEx(0, 0, "driver was mapped at %p - %p\n", pool_base, pool_size);
	DbgPrintEx(0, 0, "client process data %d - %p\n", client_pid, shared_memory_address);
#endif

	/*
	* Spawn a thread and let this function return to usermode, the client can continue its execution and clean up the hook
	* while we setup our payload. Even if it may not look clear from the kdmapper's source, right now we're executing as
	* a hook on a routine.
	*/
	HANDLE system_thread_handle;
	PsCreateSystemThread(&system_thread_handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, thread_entry, NULL);

	return STATUS_SUCCESS;
}