#pragma once
#include <Windows.h>
#include <stdint.h>
#include <vector>
#include <string>

namespace portable_executable
{
	struct reloc_info_t
	{
		uint64_t address;
		uint16_t* item;
		uint32_t count;
	};

	struct import_function_info_t
	{
		std::string name;
		uint64_t* address;
	};

	struct import_info_t
	{
		std::string module_name;
		std::vector<import_function_info_t> function_datas;
	};

	using vec_sections = std::vector<IMAGE_SECTION_HEADER>;
	using vec_relocs = std::vector<reloc_info_t>;
	using vec_imports = std::vector<import_info_t>;

	PIMAGE_NT_HEADERS64 get_nt_headers(void* image_base);
	vec_relocs get_relocs(void* image_base);
	vec_imports get_imports(void* image_base);
}