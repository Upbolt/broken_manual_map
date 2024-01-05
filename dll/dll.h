#pragma once

#include <Windows.h>
#include <winnt.h>

#include <vector>
#include <filesystem>

namespace rsh {
	class dll {
	private:
		std::string _data;
		std::vector<IMAGE_SECTION_HEADER> _sections;
		IMAGE_NT_HEADERS _headers;
	public:
		dll(const std::filesystem::path&);

		std::vector<IMAGE_SECTION_HEADER> sections() const;
		IMAGE_NT_HEADERS headers() const;
		std::string data() const;
	};
}
