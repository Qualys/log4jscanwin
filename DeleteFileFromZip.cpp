// DeleteFileFromZip.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "minizip/zip.h"
#include "minizip/unzip.h"
#include "minizip/iowin32.h"

#include <string>
#include <vector>
#include <stack>
#include <map>

#include <chrono>
#include <ctime>

typedef std::stack<std::pair<std::wstring, std::wstring>> PairStack;
typedef std::pair<std::wstring, std::wstring> StringPair;



template< class T > void SafeDelete(T*& pVal)
{
	if (pVal)
	{
		delete pVal;
		pVal = nullptr;
	}
}

template< class T > void SafeDeleteArray(T*& pVal)
{
	if (pVal)
	{
		delete[] pVal;
		pVal = nullptr;
	}
}

zipFile UnZipOpenFile(const std::wstring& file_path, zlib_filefunc64_def* ffunc)
{
	if (!ffunc)
	{
		return NULL;
	}
	return unzOpen2_64(file_path.c_str(), ffunc);
}

zipFile ZipOpenFile(const std::wstring& file_path, int append, zipcharpc* globalcomment, zlib_filefunc64_def* ffunc)
{
	if (!ffunc)
	{
		return NULL;
	}
	return zipOpen2_64(file_path.c_str(), append, globalcomment, ffunc);
}

void SplitWideString(std::wstring str, const std::wstring& token, std::vector<std::wstring>& result)
{
	while (str.size()) {
		auto index = str.find(token);
		if (index != std::wstring::npos) {
			result.push_back(str.substr(0, index));
			str = str.substr(index + token.size());
			if (str.size() == 0)
				result.push_back(str);
		}
		else {
			result.push_back(str);
			str.clear();
		}
	}
}

std::wstring A2W(const std::string& str) {
	int length_wide = MultiByteToWideChar(CP_ACP, 0, str.data(), -1, NULL, 0);
	wchar_t* string_wide = static_cast<wchar_t*>(_alloca((length_wide * sizeof(wchar_t)) + sizeof(wchar_t)));
	MultiByteToWideChar(CP_ACP, 0, str.data(), -1, string_wide, length_wide);
	std::wstring result(string_wide, length_wide - 1);
	return result;
}

std::string W2A(const std::wstring& str) {
	int length_ansi = WideCharToMultiByte(CP_ACP, 0, str.data(), -1, NULL, 0, NULL, NULL);
	char* string_ansi = static_cast<char*>(_alloca(length_ansi + sizeof(char)));
	WideCharToMultiByte(CP_ACP, 0, str.data(), -1, string_ansi, length_ansi, NULL, NULL);
	std::string result(string_ansi, length_ansi - 1);
	return result;
}

int ExtractFileArchives(const std::vector<std::wstring>& archives, PairStack& archives_mapping)
{
	int32_t			rv = ERROR_SUCCESS;
	unsigned long	bytesWritten = 0;
	//unzFile			zf = NULL;
	BYTE			buf[1024];
	wchar_t			tmpPath[_MAX_PATH + 1]{};
	wchar_t			tmpFilename[_MAX_PATH + 1]{};

	zlib_filefunc64_def zfm = { 0 };
	fill_win32_filefunc64W(&zfm);

	std::wstring current_file = archives.at(0);
	
	for (size_t i = 1; i < archives.size(); i++)
	{
		unzFile zf = unzOpen2_64(current_file.c_str(), &zfm);
		if (NULL != zf) {
			rv = unzLocateFile(zf, W2A(archives.at(i)).c_str(), false);
			if (UNZ_OK == rv) 
			{
				GetTempPath(_countof(tmpPath), tmpPath);
				GetTempFileName(tmpPath, L"qua", 0, tmpFilename);

				HANDLE h = CreateFile(tmpFilename, GENERIC_READ | GENERIC_WRITE, NULL,
					NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);

				if (h != INVALID_HANDLE_VALUE) {
					rv = unzOpenCurrentFile(zf);
					if (UNZ_OK == rv) {
						std::wcout << L"Writing " << archives.at(i).c_str() << L" to " << tmpFilename << std::endl;
						do {
							memset(buf, 0, sizeof(buf));
							rv = unzReadCurrentFile(zf, buf, sizeof(buf));
							if (rv < 0 || rv == 0) break;
							WriteFile(h, buf, rv, &bytesWritten, NULL);
						} while (rv > 0);
						unzCloseCurrentFile(zf);
					}
					CloseHandle(h);
				}

				archives_mapping.push(std::make_pair(archives.at(i), tmpFilename));

				current_file = tmpFilename;				
			}
			else {
				std::wcout << L"Failed to locate file: " << archives.at(i).c_str() << std::endl;				
				break;
			}
		}

		if (zf != NULL)
		{
			unzClose(zf);
		}
	}
	return rv;
}

int DeleteFileFromZIP(const wchar_t* zip_name, const wchar_t* del_file)
{
	bool some_was_del = false;

	wchar_t* tmp_name = new wchar_t[(wcslen(zip_name) + 5)];
	wcscpy(tmp_name, zip_name);
	wcsncat(tmp_name, L".tmp\0", 5);

	// open source and destination file
	zlib_filefunc64_def ffunc;
	fill_win32_filefunc64W(&ffunc);

	zipFile szip = unzOpen2_64(zip_name, &ffunc);
	if (szip == NULL) 
	{ 
		SafeDeleteArray(tmp_name);
		return -1; 
	}
	
	zipFile dzip = zipOpen2_64(tmp_name, APPEND_STATUS_CREATE, NULL, &ffunc);
	if (dzip == NULL) 
	{ 
		unzClose(szip); 
		SafeDeleteArray(tmp_name);
		return -1; 
	}

	// get global commentary
	unz_global_info glob_info;
	if (unzGetGlobalInfo(szip, &glob_info) != UNZ_OK) 
	{ 
		zipClose(dzip, NULL); 
		unzClose(szip);
		SafeDeleteArray(tmp_name);
		return -1; 
	}

	char* glob_comment = nullptr;
	if (glob_info.size_comment > 0)
	{
		//glob_comment = (char*)malloc(glob_info.size_comment + 1);
		glob_comment = new char[glob_info.size_comment + 1];
		
		if ((glob_comment == nullptr) && (glob_info.size_comment != 0))
		{ 
			zipClose(dzip, NULL); 
			unzClose(szip);
			SafeDeleteArray(tmp_name);
			return -1;
		}

		SecureZeroMemory(glob_comment, glob_info.size_comment + 1);

		if ((unsigned int)unzGetGlobalComment(szip, glob_comment, glob_info.size_comment + 1) != glob_info.size_comment) 
		{ 
			zipClose(dzip, NULL); 
			unzClose(szip); 
			free(glob_comment); 
			SafeDeleteArray(tmp_name);
			return -1;
		}
	}

	// copying files
	int n_files = 0;

	int rv = unzGoToFirstFile(szip);
	while (rv == UNZ_OK)
	{
		// get zipped file info
		unz_file_info unzfi;
		char dos_fn[MAX_PATH];
		if (unzGetCurrentFileInfo(szip, &unzfi, dos_fn, MAX_PATH, NULL, 0, NULL, 0) != UNZ_OK)
		{
			break;
		}

		wchar_t fn[MAX_PATH];
		OemToChar(dos_fn, fn);

		OutputDebugString(fn);
		OutputDebugString(L"\n");

		// if not need delete this file
		if (_wcsicmp(fn, del_file) == 0) // lowercase comparison
			some_was_del = true;
		else
		{

			char* extrafield = nullptr;
			char* commentary = nullptr;

			if (unzfi.size_file_extra > 0)
			{
				extrafield = new char[unzfi.size_file_extra];
			}
			if (unzfi.size_file_comment)
			{
				commentary = new char[unzfi.size_file_comment];
			}

			if (unzGetCurrentFileInfo(szip, &unzfi, dos_fn, MAX_PATH, extrafield, unzfi.size_file_extra, commentary, unzfi.size_file_comment) != UNZ_OK) 
			{
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				break; 
			}

			// open file for RAW reading
			int method;
			int level;
			if (unzOpenCurrentFile2(szip, &method, &level, 1) != UNZ_OK)
			{ 
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				break;
			}

			int size_local_extra = unzGetLocalExtrafield(szip, NULL, 0);
			if (size_local_extra < 0) 
			{
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				break; 
			}

			void* local_extra = new BYTE[size_local_extra];
			if ((local_extra == NULL) && (size_local_extra != 0)) 
			{
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				break;
			}

			if (unzGetLocalExtrafield(szip, local_extra, size_local_extra) < 0) 
			{
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				SafeDeleteArray(local_extra);
				break;
			}

			// this malloc may fail if file very large
			void* buf = new BYTE[unzfi.compressed_size];
			if ((buf == NULL) && (unzfi.compressed_size != 0)) 
			{ 
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				SafeDeleteArray(local_extra);
				break; 
			}

			// read file
			int sz = unzReadCurrentFile(szip, buf, unzfi.compressed_size);
			if ((unsigned int)sz != unzfi.compressed_size)
			{ 
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				SafeDeleteArray(local_extra);
				SafeDeleteArray(buf);
				break; 
			}

			// open destination file
			zip_fileinfo zfi;
			memcpy(&zfi.tmz_date, &unzfi.tmu_date, sizeof(tm_unz));
			zfi.dosDate = unzfi.dosDate;
			zfi.internal_fa = unzfi.internal_fa;
			zfi.external_fa = unzfi.external_fa;

			if (zipOpenNewFileInZip2(dzip, dos_fn, &zfi, local_extra, size_local_extra, extrafield, unzfi.size_file_extra, commentary, method, level, 1) != UNZ_OK) 
			{ 
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				SafeDeleteArray(local_extra);
				SafeDeleteArray(buf);
				break; 
			}

			// write file
			if (zipWriteInFileInZip(dzip, buf, unzfi.compressed_size) != UNZ_OK) 
			{ 
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				SafeDeleteArray(local_extra);
				SafeDeleteArray(buf);
				break;
			}

			if (zipCloseFileInZipRaw(dzip, unzfi.uncompressed_size, unzfi.crc) != UNZ_OK) 
			{
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				SafeDeleteArray(local_extra);
				SafeDeleteArray(buf);
				break; 
			}

			if (unzCloseCurrentFile(szip) == UNZ_CRCERROR) 
			{ 
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				SafeDeleteArray(local_extra);
				SafeDeleteArray(buf);
				break;
			}

			SafeDeleteArray(extrafield);
			SafeDeleteArray(commentary);
			SafeDeleteArray(local_extra);
			SafeDeleteArray(buf);

			n_files++;
		}

		rv = unzGoToNextFile(szip);
	}

	zipClose(dzip, glob_comment);
	unzClose(szip);

	if (glob_comment)
	{
		SafeDeleteArray(glob_comment);
	}


	// if fail
	if ((!some_was_del) || (rv != UNZ_END_OF_LIST_OF_FILE))
	{
		//_wremove(tmp_name);
		SafeDeleteArray(tmp_name);
		return -1;
	}

	_wremove(zip_name);
	if (_wrename(tmp_name, zip_name) != 0)
	{
		//free(tmp_name);
		//return -1;
	}

	// if all files were deleted
	if (n_files == 0) _wremove(zip_name);

	SafeDeleteArray(tmp_name);
	return 0;
}

int ReplaceFileInZip(
	const std::wstring& target_zip_path, 
	const std::wstring& vulnerable_zip_name, 
	const std::wstring& fixed_zip_path 
)
{
	bool file_replaced = false;

	std::wstring temp_name = target_zip_path + L".tmp";

	// open source and destination file
	zlib_filefunc64_def ffunc;
	fill_win32_filefunc64W(&ffunc);

	zipFile szip = UnZipOpenFile(target_zip_path, &ffunc);
	if (szip == NULL)
	{
		return -1;
	}

	zipFile dzip = ZipOpenFile(temp_name.c_str(), APPEND_STATUS_CREATE, NULL, &ffunc);
	if (dzip == NULL)
	{
		unzClose(szip);
		return -1;
	}

	// get global commentary
	unz_global_info glob_info;
	if (unzGetGlobalInfo(szip, &glob_info) != UNZ_OK)
	{
		zipClose(dzip, NULL);
		unzClose(szip);
		return -1;
	}

	char* glob_comment = nullptr;
	if (glob_info.size_comment > 0)
	{
		//glob_comment = (char*)malloc(glob_info.size_comment + 1);
		glob_comment = new char[glob_info.size_comment + 1];

		if ((glob_comment == nullptr) && (glob_info.size_comment != 0))
		{
			zipClose(dzip, NULL);
			unzClose(szip);
			return -1;
		}

		SecureZeroMemory(glob_comment, glob_info.size_comment + 1);

		if ((unsigned int)unzGetGlobalComment(szip, glob_comment, glob_info.size_comment + 1) != glob_info.size_comment)
		{
			zipClose(dzip, NULL);
			unzClose(szip);
			SafeDeleteArray(glob_comment);
			return -1;
		}
	}

	// copying files
	int n_files = 0;

	int rv = unzGoToFirstFile(szip);
	while (rv == UNZ_OK)
	{
		// get zipped file info
		unz_file_info unzfi;
		char dos_fn[MAX_PATH];
		if (unzGetCurrentFileInfo(szip, &unzfi, dos_fn, MAX_PATH, NULL, 0, NULL, 0) != UNZ_OK)
		{
			break;
		}

		wchar_t fn[MAX_PATH];
		OemToChar(dos_fn, fn);

		OutputDebugString(fn);
		OutputDebugString(L"\n");

		{
			
			char* extrafield = nullptr;
			char* commentary = nullptr;

			if (unzfi.size_file_extra > 0)
			{
				extrafield = new char[unzfi.size_file_extra];
			}
			if (unzfi.size_file_comment)
			{
				commentary = new char[unzfi.size_file_comment];
			}

			if (unzGetCurrentFileInfo(szip, &unzfi, dos_fn, MAX_PATH, extrafield, unzfi.size_file_extra, commentary, unzfi.size_file_comment) != UNZ_OK)
			{
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				break;
			}

			// open file for RAW reading
			int method;
			int level;
			if (unzOpenCurrentFile2(szip, &method, &level, 1) != UNZ_OK)
			{
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				break;
			}

			int size_local_extra = unzGetLocalExtrafield(szip, NULL, 0);
			if (size_local_extra < 0)
			{
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				break;
			}

			void* local_extra = new BYTE[size_local_extra];
			if ((local_extra == NULL) && (size_local_extra != 0))
			{
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				break;
			}

			if (unzGetLocalExtrafield(szip, local_extra, size_local_extra) < 0)
			{
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				SafeDeleteArray(local_extra);
				break;
			}

			void* buf = nullptr;
			ULONG compressed_size = 0;
			int sz = 0;
			bool vul_file_found = false;
			if (_wcsicmp(fn, vulnerable_zip_name.c_str()) == 0)
			{
				// read file into buffer
				HANDLE handle_fixed_zip = CreateFile(fixed_zip_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
				if (handle_fixed_zip == INVALID_HANDLE_VALUE)
				{
					std::cout << "Error " << GetLastError();
					SafeDeleteArray(extrafield);
					SafeDeleteArray(commentary);
					SafeDeleteArray(local_extra);
					break;
				}

				compressed_size = GetFileSize(handle_fixed_zip, NULL);

				buf = new BYTE[compressed_size];
				if ((buf == NULL) && (compressed_size != 0))
				{
					SafeDeleteArray(extrafield);
					SafeDeleteArray(commentary);
					SafeDeleteArray(local_extra);
					CloseHandle(handle_fixed_zip);
					break;
				}

				if (0 == ReadFile(handle_fixed_zip, buf, compressed_size, nullptr, nullptr))
				{
					std::cout << "Error " << GetLastError();
					SafeDeleteArray(extrafield);
					SafeDeleteArray(commentary);
					SafeDeleteArray(local_extra);
					CloseHandle(handle_fixed_zip);
					break;
				}

				CloseHandle(handle_fixed_zip);
				vul_file_found = true;
			}
			else
			{
				buf = new BYTE[unzfi.compressed_size];
				if ((buf == NULL) && (unzfi.compressed_size != 0))
				{
					SafeDeleteArray(extrafield);
					SafeDeleteArray(commentary);
					SafeDeleteArray(local_extra);
					break;
				}
				compressed_size = unzfi.compressed_size;

				// read file
				sz = unzReadCurrentFile(szip, buf, compressed_size);
				if ((unsigned int)sz != compressed_size)
				{
					SafeDeleteArray(extrafield);
					SafeDeleteArray(commentary);
					SafeDeleteArray(local_extra);
					SafeDeleteArray(buf);
					break;
				}
			}			

			// open destination file
			zip_fileinfo zfi;
			memcpy(&zfi.tmz_date, &unzfi.tmu_date, sizeof(tm_unz));
			zfi.dosDate = unzfi.dosDate;
			zfi.internal_fa = unzfi.internal_fa;
			zfi.external_fa = unzfi.external_fa;

			if (vul_file_found)
			{
				//zipper_add_buf(dzip, dos_fn, buf, compressed_size, method, &zfi);
				if (zipOpenNewFileInZip2(dzip, dos_fn, &zfi, local_extra, size_local_extra, extrafield, unzfi.size_file_extra, commentary,
					method, level, (compressed_size > 0xffffffff) ? 1 : 0) != UNZ_OK)
				{
					SafeDeleteArray(extrafield);
					SafeDeleteArray(commentary);
					SafeDeleteArray(local_extra);
					SafeDeleteArray(buf);
					break;
				}

				if (zipWriteInFileInZip(dzip, buf, compressed_size) != UNZ_OK)
				{
					SafeDeleteArray(extrafield);
					SafeDeleteArray(commentary);
					SafeDeleteArray(local_extra);
					SafeDeleteArray(buf);
					break;
				}

				if (zipCloseFileInZip(dzip) != UNZ_OK)
				{
					SafeDeleteArray(extrafield);
					SafeDeleteArray(commentary);
					SafeDeleteArray(local_extra);
					SafeDeleteArray(buf);
					break;
				}				
			}
			else
			{							
                if (zipOpenNewFileInZip2(dzip, dos_fn, &zfi, local_extra, size_local_extra, extrafield, unzfi.size_file_extra, commentary, method, level, 1) != UNZ_OK)
                {
                    SafeDeleteArray(extrafield);
                    SafeDeleteArray(commentary);
                    SafeDeleteArray(local_extra);
                    SafeDeleteArray(buf);
                    break;
                }

                // write file
                if (zipWriteInFileInZip(dzip, buf, unzfi.compressed_size) != UNZ_OK)
                {
                    SafeDeleteArray(extrafield);
                    SafeDeleteArray(commentary);
                    SafeDeleteArray(local_extra);
                    SafeDeleteArray(buf);
                    break;
                }

                if (zipCloseFileInZipRaw(dzip, unzfi.uncompressed_size, unzfi.crc) != UNZ_OK)
                {
                    SafeDeleteArray(extrafield);
                    SafeDeleteArray(commentary);
                    SafeDeleteArray(local_extra);
                    SafeDeleteArray(buf);
                    break;
                }
            }

			if (unzCloseCurrentFile(szip) == UNZ_CRCERROR)
			{
				SafeDeleteArray(extrafield);
				SafeDeleteArray(commentary);
				SafeDeleteArray(local_extra);
				SafeDeleteArray(buf);
				break;
			}

			SafeDeleteArray(extrafield);
			SafeDeleteArray(commentary);
			SafeDeleteArray(local_extra);
			SafeDeleteArray(buf);

			if (vul_file_found)
			{
				file_replaced = true;
			}

			n_files++;
		}

		rv = unzGoToNextFile(szip);
	}

	zipClose(dzip, glob_comment);
	unzClose(szip);

	if (glob_comment)
	{
		SafeDeleteArray(glob_comment);
	}


	// if fail
	if ((!file_replaced) || (rv != UNZ_END_OF_LIST_OF_FILE))
	{
		_wremove(temp_name.c_str());		
		return -1;
	}

	_wremove(target_zip_path.c_str());
	if (_wrename(temp_name.c_str(), target_zip_path.c_str()) != 0)
	{
		return -1;
	}

	return 0;
}

int RemediateFileArchive(const std::wstring& vulnerable_file_path)
{
	std::vector<std::wstring> result;
	SplitWideString(vulnerable_file_path, L"!", result);

	// Copy original parent to temp parent1
	wchar_t	tmpPath[_MAX_PATH + 1]{};
	wchar_t tmpFilename[_MAX_PATH + 1]{};
	GetTempPath(_countof(tmpPath), tmpPath);
	GetTempFileName(tmpPath, L"qua", 0, tmpFilename);

	if (FALSE == CopyFile(result[0].c_str(), tmpFilename, FALSE))
	{
		return -1;
	}

	PairStack archives_mapping;

	archives_mapping.push(std::make_pair(result[0], tmpFilename));

	if (ExtractFileArchives(result, archives_mapping))
	{
		std::wcout << L"Failed to extract archives " << vulnerable_file_path << std::endl;
		return -1;
	}

	// 1. Pop the first jar and fix it. It is a vulnerable jar
	auto last_visited = archives_mapping.top();
	archives_mapping.pop();

	if (DeleteFileFromZIP(last_visited.second.c_str(), L"WEB-INF/web.xml"))
	{
		std::wcout << L"Failed to delete vulnerable class from archive" << std::endl;
		return -1;
	}

	while (!archives_mapping.empty())
	{
		auto parent_jar_mapping = archives_mapping.top();
		archives_mapping.pop();

		if (ReplaceFileInZip(parent_jar_mapping.second, last_visited.first, last_visited.second))
		{
			std::wcout << L"Failed to repackage archive" << std::endl;
			return -1;
		}

		last_visited = parent_jar_mapping;
	}

	// 2 - 30 second

	// Make backup of original jar
	auto original_backup = result[0] + L".backup";
	if (_wrename(result[0].c_str(), original_backup.c_str()) != 0)
	{
		return -1;
	}

	// replace fixed jar with original
	if (_wrename(tmpFilename, result[0].c_str()) != 0)
	{
		return -1;
	}

	// delete the backup file

	// delete entry from log4j_findings.out

	// update remdiation report 

	Sleep(10000);

	return 0;
}

int main(int argc, wchar_t** argv)
{
	MessageBox(NULL, L"Debug", L"", MB_OK);

	auto t_start = std::chrono::high_resolution_clock::now();
	//std::wstring VulnFile = L"D:\\Log4JUtility\\test\\OuterJar.zip!OuterJar.jar!libs/dependencies/InnerJar.jar!Sample4.jar";

	std::vector<std::wstring> vul_files;
	/*vul_files.push_back(L"D:\\Log4JUtility\\test\\OuterJar.zip!OuterJar.jar!libs/dependencies/InnerJar.jar!Sample4.jar");
	vul_files.push_back(L"D:\\Log4JUtility\\test\\OuterJar1.zip!OuterJar.jar!libs/dependencies/InnerJar.jar!Sample4.jar");
	vul_files.push_back(L"D:\\Log4JUtility\\test\\OuterJar2.zip!OuterJar.jar!libs/dependencies/InnerJar.jar!Sample4.jar");
	vul_files.push_back(L"D:\\Log4JUtility\\test\\OuterJar3.zip!OuterJar.jar!libs/dependencies/InnerJar.jar!Sample4.jar");	
	vul_files.push_back(L"D:\\Log4JUtility\\test\\OuterJar4.zip!OuterJar.jar!libs/dependencies/InnerJar.jar!Sample4.jar");*/

	vul_files.push_back(L"D:\\Log4JUtility\\test\\HelloWorldApp.ear!HelloWorldWeb.war");

	for (const auto& VulnFile : vul_files)
	{
		RemediateFileArchive(VulnFile);

		std::wcout << "\nProcessed : " << VulnFile << std::endl << std::endl;

		auto t_end = std::chrono::high_resolution_clock::now();

		auto time_since_start = std::chrono::duration<double>(t_end - t_start).count();

		if (time_since_start > 50)
		{
			std::cout << "time out expire. Exiting. Seconds " << time_since_start;
			break;
		}
	}

	return 0;
}
