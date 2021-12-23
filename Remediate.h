#pragma once

#include "minizip/ioapi.h"

class RemediateLog4J
{
	zlib_filefunc64_def ffunc_;
public:
	RemediateLog4J();
	~RemediateLog4J();
	int RemediateFileArchive(const std::wstring& vulnerable_file_path);
private:
	int DeleteFileFromZIP(const std::wstring& zip_name, const std::wstring& del_file);
	int ReplaceFileInZip(
		const std::wstring& target_zip_path,
		const std::wstring& vulnerable_zip_name,
		const std::wstring& fixed_zip_path
	);
	int FixArchive(const std::wstring& target_zip_path,
		const std::wstring& vulnerable_zip_name,
		const std::wstring& fixed_zip_path,
		bool delete_file = false);
	int ReadFileContent(std::wstring file_path, void** buf, PULONG size);
};

constexpr DWORD BUFFER_READ_SIZE = 256;
constexpr DWORD SIGNATURE_ITEM_LENGTH = 4;

bool RemediateFromSignatureReport();
bool RemediateFile(const std::wstring& file);
