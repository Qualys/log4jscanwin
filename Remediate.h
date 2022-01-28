#pragma once

namespace log4jremediate {

	constexpr DWORD SIGNATURE_ITEM_LENGTH = 4;

	class RemediateLog4JFile {
	public:
		RemediateLog4JFile() = default;

		~RemediateLog4JFile() = default;

		DWORD RemediateFileArchive(const std::wstring& vulnerable_file_path);

	private:
		/* Cleanup temporary files*/
		void CleanupTempFiles(const std::unordered_set<std::wstring>& setTempLocs);
	};

	class RemediateLog4JSigReport {
	public:
		static DWORD RemediateFromSignatureReport();
	};
}
