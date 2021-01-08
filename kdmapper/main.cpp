#include "kdmapper.hpp"

int main(const int argc, char** argv)
{
	if (argc != 2 || std::filesystem::path(argv[1]).extension().string().compare(".sys"))
	{
		std::cout << "[-] Incorrect usage" << std::endl;
		return -1;
	}

	const std::string driver_path = argv[1];

	if (!std::filesystem::exists(driver_path))
	{
		std::cout << "[-] File " << driver_path << " doesn't exist" << std::endl;
		return -1;
	}

	HANDLE iqvw64e_device_handle = intel_driver::load();

	if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "[-] Failed to load driver iqvw64e.sys" << std::endl;
		return -1;
	}

	if (!kdmapper::map_driver(iqvw64e_device_handle, driver_path))
	{
		std::cout << "[-] Failed to map " << driver_path << std::endl;
		intel_driver::unload(iqvw64e_device_handle);
		return -1;
	}

	intel_driver::unload(iqvw64e_device_handle);

	/*
	* let's make sure no one in the system can detect this after it's mapped by completely
	* randomizing the entirety of the vulnerable driver in our memory.
	*/
	for (auto i = 0; i < sizeof(intel_driver_resource::driver); i++)
	{
		uint8_t random = __rdtsc() % 0xff;

		memcpy(const_cast<uint8_t*>(&intel_driver_resource::driver[i]), &random, 1);
	}

	std::cout << "[<] Removed the intel driver from memory" << std::endl;

	/*
	* Now we can start testing the comms' features.
	*/

	std::cout << "[+] Success, initiating communication with the mapped kernel payload..." << std::endl;

	for (auto i = 0; i < 3; i++)
	{
		/*
		* These pings should appear in DbgView. Please tick "Capture Kernel" and execute as administrator
		* if you want to see them.
		*/

		kdmapper::comms::ping();
	}

	std::cout << "[+] 3 pings have just appeared in DbgView / Windbg :), remember to capture kernel!" << std::endl;

	std::cout << "[+] Handle-less virtual memory modification test starting..." << std::endl;

	uint32_t value = 1337;
	uint32_t value_buffer = 0;

	kdmapper::comms::mm_copy_virtual_memory(GetCurrentProcessId(), reinterpret_cast<uint64_t>(&value),
		GetCurrentProcessId(), reinterpret_cast<uint64_t>(&value_buffer), sizeof(uint32_t));

	if (value == value_buffer)
	{
		std::cout << "[+] The memory operation test was successful." << std::endl;
	}

	std::cout << "[+] Testing memory operation wrappers..." << std::endl;

	if (value == kdmapper::comms::read_vm<uint32_t>(GetCurrentProcessId(), reinterpret_cast<uint64_t>(&value_buffer)))
	{
		std::cout << "[+] Reading wrapper works..." << std::endl;
	}

	std::cout << "[+] Zeroing the testing buffer..." << std::endl;

	value_buffer = 0;
	kdmapper::comms::write_vm<uint32_t>(GetCurrentProcessId(), reinterpret_cast<uint64_t>(&value_buffer), value);

	if (value == value_buffer) 
	{
		std::cout << "[+] Writing wrapper works..." << std::endl;
	}

	std::cout << "[+] Tests finished, memory R/W without a process handle capabilities have been confirmed, the kernel payload will now self destruct." << std::endl;

	kdmapper::comms::unload_payload();
}