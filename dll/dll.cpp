#include "dll.hpp"

#include "../util/file.hpp"

namespace rsh {
	dll::dll(const std::filesystem::path& path) {
		const std::string image = util::file::read<std::ios::binary>(path);
		const auto dos_header = std::bit_cast<IMAGE_DOS_HEADER*>(image.data());

		if (dos_header->e_magic != 0x5A4D) {
			throw std::runtime_error("invalid dll file");
		}

		const auto nt_headers = std::bit_cast<IMAGE_NT_HEADERS*>(image.data() + dos_header->e_lfanew);
		auto current_section = IMAGE_FIRST_SECTION(nt_headers);

		for (std::size_t i = 0; i != nt_headers->FileHeader.NumberOfSections; ++i, ++current_section) {
			//if (current_section->SizeOfRawData != 0) {
				this->_sections.push_back(*current_section);
			//}
		}

		this->_headers = *nt_headers;
		this->_data = image;
	}

	std::vector<IMAGE_SECTION_HEADER> dll::sections() const {
		return this->_sections;
	}

	IMAGE_NT_HEADERS dll::headers() const {
		return this->_headers;
	}

	std::string dll::data() const {
		return this->_data;
	}
}
