#pragma once
#include <Windows.h>
#include <string>
#include <filesystem>
#include "intel_driver.hpp"

namespace service
{
	bool register_and_start(const std::string& driver_path);
	bool stop_and_remove(const std::string& driver_name);
};