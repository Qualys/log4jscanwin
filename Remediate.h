#pragma once

namespace log4jremediate {

	constexpr DWORD BUFFER_READ_SIZE = 256;
	constexpr DWORD SIGNATURE_ITEM_LENGTH = 4;

	class RemediateLog4JFile {
		zlib_filefunc64_def ffunc_;

	public:
		RemediateLog4JFile() {
			fill_win32_filefunc64W(&ffunc_);
		}

		~RemediateLog4JFile() = default;

		DWORD RemediateFileArchive(const std::wstring& vulnerable_file_path);

	private:
		__inline int DeleteFileFromZIP(const std::wstring& zip_name, const std::wstring& del_file) {
			return FixArchive(zip_name, del_file, L"", true);
		}

		__inline int ReplaceFileInZip(const std::wstring& target_zip_path, const std::wstring& vulnerable_zip_name, const std::wstring& fixed_zip_path) {
			return FixArchive(target_zip_path, vulnerable_zip_name, fixed_zip_path, false);
		}

		int FixArchive(const std::wstring& target_zip_path,
			const std::wstring& vulnerable_zip_name,
			const std::wstring& fixed_zip_path,
			bool delete_file = false);

		int ReadFileContent(const std::wstring &file_path, std::vector<BYTE>& buf, PULONG size);
	};

	class RemediateLog4JSigReport {
	public:
		static DWORD RemediateFromSignatureReport();
	};
}
