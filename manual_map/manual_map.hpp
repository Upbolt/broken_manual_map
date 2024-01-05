#pragma once

#include <filesystem>

namespace injection {
	struct manual_map_options {
		bool exclude_headers;
		bool remove_extra_sections;
		bool adjust_protections;
		void* reserved;
	};

	void manual_map(const std::filesystem::path& dll_path, const std::wstring_view& process_name, const manual_map_options& = {});
}
