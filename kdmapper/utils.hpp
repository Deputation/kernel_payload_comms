#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>

#include "nt.hpp"

namespace utils
{
	bool read_file_to_memory(const std::string& file_path, std::vector<uint8_t>* out_buffer);
	bool create_file_from_memory(const std::string& desired_file_path, const char* address, size_t size);
	uint64_t get_kernel_module_address(const std::string& module_name);
}