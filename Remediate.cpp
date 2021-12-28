
#include "stdafx.h"
#include "Reports.h"
#include "Remediate.h"
#include "Utils.h"

namespace log4jremediate {
	const std::wregex line1_regex(L"Source: Manifest Vendor: ([^,]*), Manifest Version: ([^,]*), JNDI Class: ([^,]*), Log4j Vendor: ([^,]*), Log4j Version: ([^,]*)");
	const std::wregex line2_regex(L"Path=(.*)");

	__inline zipFile UnZipOpenFile(const std::wstring& file_path, zlib_filefunc64_def* ffunc) {
		if (!ffunc) {
			return nullptr;
		}

		return unzOpen2_64(file_path.c_str(), ffunc);
	}

	__inline zipFile ZipOpenFile(const std::wstring& file_path, int append, zipcharpc* globalcomment, zlib_filefunc64_def* ffunc) {
		if (!ffunc) {
			return nullptr;
		}

		return zipOpen2_64(file_path.c_str(), append, globalcomment, ffunc);
	}

	int ExtractFileArchives(const std::vector<std::wstring>& archives, PairStack& archives_mapping, std::unordered_set<std::wstring>& tempLocset) {
		if (archives.empty()) {
			return UNZ_BADZIPFILE;
		}

		int rv{ UNZ_OK };
		ULONG	bytesWritten{ 0 };
		std::vector<BYTE> buf(1024, 0);
		wchar_t tmpPath[_MAX_PATH + 1]{};
		wchar_t tmpFilename[_MAX_PATH + 1]{};

		zlib_filefunc64_def zfm = { 0 };
		fill_win32_filefunc64W(&zfm);

		std::wstring current_file{ archives.at(0) };

		for (size_t i = 1; i < archives.size(); i++) {
			unzFile zf = unzOpen2_64(current_file.c_str(), &zfm);

			if (zf) {
				rv = unzLocateFile(zf, W2A(archives[i]).c_str(), false);

				if (UNZ_OK == rv) {
					GetTempPath(_countof(tmpPath), tmpPath);
					GetTempFileName(tmpPath, L"qua_rem", 0, tmpFilename);

					HANDLE h = CreateFile(tmpFilename, GENERIC_READ | GENERIC_WRITE, 0,
						nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);

					if (h != INVALID_HANDLE_VALUE) {
						rv = unzOpenCurrentFile(zf);

						if (UNZ_OK == rv) {
							do {
								std::fill(buf.begin(), buf.end(), 0);

								rv = unzReadCurrentFile(zf, buf.data(), static_cast<unsigned int>(buf.size()));

								if (rv < 0 || rv == 0) {
									break;
								}

								WriteFile(h, buf.data(), rv, &bytesWritten, nullptr);

							} while (rv > 0);

							unzCloseCurrentFile(zf);
						}

						CloseHandle(h);
					}

					archives_mapping.emplace(archives[i], tmpFilename);
					tempLocset.emplace(tmpFilename);

					current_file = tmpFilename;
				}
				else {
					LOG_MESSAGE(L"Failed to locate file: %s", archives[i].c_str());
					break;
				}
			}

			if (zf) {
				unzClose(zf);
			}
		}

		return rv;
	}

	void log4jremediate::RemediateLog4JFile::CleanupTempFiles(std::unordered_set<std::wstring>& setTempLocs)
	{

		for (auto& filename : setTempLocs)
		{
			// If we are unable to File Attributes, it simply means file doesn't exist
			//The variable are kept purposely. Helps in debugging.
			const bool bFileExists = (GetFileAttributes(filename.c_str()) != INVALID_FILE_ATTRIBUTES);
			if (bFileExists)
			{
				if (!DeleteFile(filename.c_str()))
				{
					LogStatusMessage(L"Fail to delete %s; Win32 error: %d\n", filename.c_str(), GetLastError());
				}
			}
		}
	}

	DWORD ReadSignatureReport(const std::wstring& report, std::vector<CReportVulnerabilities>& result) {
		DWORD status{ ERROR_SUCCESS };
		std::wstringstream wss;
		std::vector<std::wstring> lines;

		std::wifstream wif(report);

		if (!wif.is_open()) {			
			LOG_MESSAGE(L"No signature report found in %s", report.c_str());
			goto END;
		}

		wif.imbue(std::locale(std::locale::empty(), new std::codecvt_utf8<wchar_t>));
		wss << wif.rdbuf();
		SplitWideString(wss.str(), L"\n", lines);

		if (lines.size() % 4 != 0) {
			status = ERROR_INVALID_DATA;
			LOG_WIN32_MESSAGE(status, L"Invalid signature report %s", report.c_str());
			goto END;
		}

		for (size_t index = 0; index < lines.size(); index += SIGNATURE_ITEM_LENGTH) {
			std::wsmatch wsm1, wsm2;
			if (std::regex_search(lines[index].cbegin(), lines[index].cend(), wsm1, line1_regex)) {
				if (std::regex_search(lines[index + 1].cbegin(), lines[index + 1].cend(), wsm2, line2_regex)) {
					CReportVulnerabilities report(wsm2[1].str(), wsm1[2].str(), wsm1[1].str(), false, false, false, 
						(wsm1[3].str() == L"Found"), false, wsm1[5].str(), wsm1[4].str(), false, false, false, false, L"");
					result.push_back(std::move(report));
				}
			}
			else {
				status = ERROR_INVALID_DATA;
				LOG_WIN32_MESSAGE(status, L"Unable to parse signature report %s", report.c_str());
				goto END;
			}
		}

	END:
		return status;
	}

	DWORD ModifySigReportEntry(const CReportVulnerabilities& modify) {
		DWORD status{ ERROR_SUCCESS };
		std::vector<CReportVulnerabilities> signature_report;

		std::wstring sig_report_file = GetSignatureReportFilename();

		status = ReadSignatureReport(sig_report_file, signature_report);
		if (status != ERROR_SUCCESS) {
			LOG_WIN32_MESSAGE(status, L"Failed to read signature report %s", sig_report_file.c_str());
		}
		else {
			std::wofstream sig_file(sig_report_file, std::ios::trunc | std::ios::out);
			sig_file.imbue(std::locale(std::locale::empty(), new std::codecvt_utf8<wchar_t>));

			if (!sig_file.is_open()) {
				status = ERROR_FILE_NOT_FOUND;
				LOG_MESSAGE(L"Failed to open signature report %s, err: %S", sig_report_file.c_str(), strerror(errno));
			}
			else {
				for (auto& item : signature_report) {

					item.detectedJNDILookupClass = (item.file != modify.file) ? item.detectedJNDILookupClass : false;

					sig_file << L"Source: Manifest Vendor: " << item.manifestVendor
						<< L", Manifest Version: " << item.manifestVersion
						<< L", JNDI Class: " << (item.detectedJNDILookupClass ? L"Found" : L"NOT Found")
						<< L", Log4j Vendor: " << item.log4jVendor
						<< L", Log4j Version: " << item.log4jVersion << "\n"
						<< L"Path=" << item.file << "\n"
						<< item.log4jVendor << " " << item.log4jVersion << "\n"
						<< L"------------------------------------------------------------------------\n";

					sig_file.flush();
				}
			}
		}

		return status;
	}

	DWORD RemediateLog4JSigReport::RemediateFromSignatureReport() {
		DWORD status{};
		DWORD report_status{};  // record error inside loop
		std::wstring sig_report_file;
		std::wstring rem_report_file;
		RemediateLog4JFile remediator;
    
		try
		{
			sig_report_file = GetSignatureReportFilename();
			rem_report_file = GetRemediationReportFilename();

			// Truncate/Create remediation report
			std::wofstream sig_file(rem_report_file, std::ios::trunc | std::ios::out);
			sig_file.close();

			status = ReadSignatureReport(sig_report_file, repVulns);
			if (status != ERROR_SUCCESS) {
				LOG_MESSAGE(L"Failed to read signature report: %s", sig_report_file.c_str());
				goto END;
			}

			if (repVulns.empty()) {
				LOG_MESSAGE(L"No vulnerabilities found in report: %s", sig_report_file.c_str());
				goto END;
			}

			for (auto& vuln : repVulns) {
				if (!vuln.detectedJNDILookupClass) {
					continue; // Not vulnerable
				}

				if (IsCVE202144228Mitigated(W2A(vuln.log4jVendor), vuln.detectedJNDILookupClass, W2A(vuln.log4jVersion)) ||
					IsCVE202145046Mitigated(W2A(vuln.log4jVendor), vuln.detectedJNDILookupClass, W2A(vuln.log4jVersion))) {
					continue; // Not vulnerable
				}

				LOG_MESSAGE(L"Processing file: %s", vuln.file.c_str());

				status = remediator.RemediateFileArchive(vuln.file);
				if (status != ERROR_SUCCESS) {
					// Failure logs added to RemediateFileArchive
					report_status = status;
				}
				else { // Remediation success

					LOG_MESSAGE(L"Fixed file: %s", vuln.file.c_str());

					vuln.cve202144228Mitigated = true;
					vuln.cve202145046Mitigated = true;

					// Modify entry in signature file
					status = ModifySigReportEntry(vuln);
					if (status != ERROR_SUCCESS) {
						report_status = status;
						LOG_WIN32_MESSAGE(status, L"Failed to modify item in signature report: %s", vuln.file.c_str());
					}
				}

				// Update report
				status = AddToRemediationReport(vuln);
				if (status != ERROR_SUCCESS) {
					report_status = status;
					LOG_WIN32_MESSAGE(status, L"Failed to add item to remediation report %s", vuln.file.c_str());
				}
			}
		}
		catch (std::bad_alloc&) {
			status = ERROR_OUTOFMEMORY;
			LOG_WIN32_MESSAGE(status, L"Failed to allocate memory in %s", __func__);
		}
		catch (std::exception& e) {
			status = ERROR_INVALID_OPERATION;
			LOG_WIN32_MESSAGE(status, L"Exception %S caught in %s", e.what(), __func__);
		}

	END:

		return (report_status != ERROR_SUCCESS ? report_status : status);
	}

	DWORD RemediateLog4JFile::RemediateFileArchive(const std::wstring& vulnerable_file_path) {
		DWORD status{};
		wchar_t	tmpPath[_MAX_PATH + 1]{};
		wchar_t tmpFilename[_MAX_PATH + 1]{};
		PairStack archives_mapping;
		std::vector<std::wstring> result;
		std::unordered_set<std::wstring> setTempLocs;

		try {
			SplitWideString(vulnerable_file_path, L"!", result);

			if (result.empty()) {
				status = ERROR_INVALID_DATA;
				LOG_WIN32_MESSAGE(status, L"No file path found in %s", vulnerable_file_path.c_str());
				return status;
			}

			// check if file is read only then do not process the jar

			DWORD fileAttr = GetFileAttributes(result[0].c_str());
			if (fileAttr & FILE_ATTRIBUTE_READONLY)
			{
				status = ERROR_ACCESS_DENIED;
				LOG_WIN32_MESSAGE(status, L"Failed to fix %s because it is read only", result[0].c_str());
				return status;
			}

			// Copy original parent to temp	
			GetTempPath(_countof(tmpPath), tmpPath);
			// LJR for Log4J remediation
			GetTempFileName(tmpPath, L"ljr", 0, tmpFilename);

			if (FALSE == CopyFile(result[0].c_str(), tmpFilename, FALSE)) {
				status = GetLastError();
				LOG_WIN32_MESSAGE(status, L"Failed to copy %s to %s", result[0].c_str(), tmpFilename);
				return status;
			}			

			// Map outermost file with corresponding temp file
			archives_mapping.emplace(result[0], tmpFilename);

			//Add to set of delete files
			setTempLocs.emplace(tmpFilename);

			if (ExtractFileArchives(result, archives_mapping, setTempLocs)) {
				status = ERROR_INVALID_OPERATION;
				LOG_WIN32_MESSAGE(status, L"Failed to extract file archives from %s", vulnerable_file_path.c_str());
				return status;
			}

			// Pop the stack and fix topmost jar.
			auto last_visited = archives_mapping.top();
			archives_mapping.pop();

			if (DeleteFileFromZIP(last_visited.second.c_str(), L"org/apache/logging/log4j/core/lookup/JndiLookup.class")) {
				status = ERROR_INVALID_OPERATION;
				LOG_WIN32_MESSAGE(status, L"Failed to delete JndiLookup.class from archive: %s", last_visited.second.c_str());
				return status;
			}

			while (!archives_mapping.empty()) {
				auto parent_jar_mapping = archives_mapping.top();
				archives_mapping.pop();

				if (ReplaceFileInZip(parent_jar_mapping.second, last_visited.first, last_visited.second)) {
					status = ERROR_INVALID_OPERATION;
					LOG_WIN32_MESSAGE(status, L"Failed to repackage fixed %s into %s", last_visited.first.c_str(), parent_jar_mapping.second.c_str());
					return status;
				}

				last_visited = parent_jar_mapping;
			}

			// Make backup of original jar
			auto original_backup = result[0] + L".backup";
			if (!MoveFile(result[0].c_str(), original_backup.c_str())) {
				status = GetLastError();
				LOG_WIN32_MESSAGE(status, L"Failed to rename %s to %s", result[0].c_str(), original_backup.c_str());
				return status;
			}

			// Add backup file to the set of delete files 
			setTempLocs.emplace(original_backup);

			// replace fixed jar with original
			if (!MoveFile(tmpFilename, result[0].c_str())) {
				status = GetLastError();
				LOG_WIN32_MESSAGE(status, L"Failed to rename %s to %s", tmpFilename, result[0].c_str());
				return status;
			}

			LOG_MESSAGE("Copied fixed file: %s", result[0].c_str());

			// Delete temporary files
			CleanupTempFiles(setTempLocs);			
		}
		catch (std::bad_alloc&) {
			status = ERROR_OUTOFMEMORY;
			LOG_WIN32_MESSAGE(status, L"Failed to allocate memory in %s", __func__);
		}
		catch (std::exception& e) {
			status = ERROR_INVALID_OPERATION;
			LOG_WIN32_MESSAGE(status, L"Exception %S caught in %s", e.what(), __func__);
		}		

		return status;
	}

	int RemediateLog4JFile::FixArchive(const std::wstring& target_zip_path, const std::wstring& vulnerable_zip_name,
		const std::wstring& fixed_zip_path, bool delete_file) {

		std::wstring temp_name{ target_zip_path };
		temp_name.append(L".tmp");

		zipFile szip = UnZipOpenFile(target_zip_path, &ffunc_);
		if (!szip) {
			return 1;
		}

		zipFile dzip = ZipOpenFile(temp_name.c_str(), APPEND_STATUS_CREATE, nullptr, &ffunc_);
		if (!dzip) {
			unzClose(szip);
			return 1;
		}

		// get global commentary
		unz_global_info glob_info;
		if (unzGetGlobalInfo(szip, &glob_info) != UNZ_OK) {
			zipClose(dzip, nullptr);
			unzClose(szip);
			return 1;
		}

		std::vector<char> glob_comment;
		if (glob_info.size_comment > 0) {
			glob_comment.resize(glob_info.size_comment + 1, '\0');

			if (static_cast<uLong>(unzGetGlobalComment(szip, glob_comment.data(), glob_info.size_comment + 1)) != glob_info.size_comment) {
				zipClose(dzip, nullptr);
				unzClose(szip);
				return 1;
			}
		}

		int rv = unzGoToFirstFile(szip);

		while (rv == UNZ_OK) {
			// get zipped file info
			unz_file_info unzfi;
			char dos_fn[MAX_PATH];
			if (unzGetCurrentFileInfo(szip, &unzfi, dos_fn, MAX_PATH, nullptr, 0, nullptr, 0) != UNZ_OK) {
				break;
			}

			std::wstring file = A2W(dos_fn);

			bool file_found = false;

			if (_wcsicmp(file.c_str(), vulnerable_zip_name.c_str()) == 0) {
				file_found = true;
			}

			// if not need delete this file
			if (file_found && delete_file) { // lowercase comparison
				rv = unzGoToNextFile(szip);
				continue;
			}
			else {
				std::vector<char> extrafield;
				std::vector<char> commentary;

				if (unzfi.size_file_extra > 0) {
					extrafield.resize(unzfi.size_file_extra);
				}
				if (unzfi.size_file_comment) {
					commentary.resize(unzfi.size_file_comment);
				}

				if (unzGetCurrentFileInfo(szip, &unzfi, dos_fn, MAX_PATH, extrafield.data(), unzfi.size_file_extra, commentary.data(), unzfi.size_file_comment) != UNZ_OK) {
					break;
				}

				int method{};
				int level{};

				// open file for RAW reading
				if (unzOpenCurrentFile2(szip, &method, &level, 1) != UNZ_OK) {
					break;
				}

				int size_local_extra = unzGetLocalExtrafield(szip, nullptr, 0);
				if (size_local_extra < 0) {
					break;
				}

				std::vector<BYTE> local_extra(size_local_extra);

				if (unzGetLocalExtrafield(szip, local_extra.data(), size_local_extra) < 0) {
					break;
				}

				std::vector<BYTE> buf;
				ULONG file_size = 0;
				// found the file that needs to be replaced
				if (file_found && !delete_file) {
					if (ReadFileContent(fixed_zip_path, buf, &file_size)) {
						break;
					}
				}
				else {
					// this may fail if file very large
					buf.resize(unzfi.compressed_size, '\0');

					// read file
					int sz = unzReadCurrentFile(szip, buf.data(), unzfi.compressed_size);
					if (static_cast<uLong>(sz) != unzfi.compressed_size) {
						break;
					}

					file_size = unzfi.compressed_size;
				}

				// open destination file
				zip_fileinfo zfi;
				memcpy(&zfi.tmz_date, &unzfi.tmu_date, sizeof(tm_unz));
				zfi.dosDate = unzfi.dosDate;
				zfi.internal_fa = unzfi.internal_fa;
				zfi.external_fa = unzfi.external_fa;

				if (zipOpenNewFileInZip2(dzip, dos_fn, &zfi, local_extra.data(), size_local_extra, extrafield.data(),
					unzfi.size_file_extra, commentary.data(), method, level, (file_found && !delete_file) ? 0 : 1) != UNZ_OK) {
					break;
				}

				// write file
				if (zipWriteInFileInZip(dzip, buf.data(), file_size) != UNZ_OK) {
					break;
				}

				if (zipCloseFileInZipRaw(dzip, (file_found && !delete_file) ? 0 : unzfi.uncompressed_size,
					(file_found && !delete_file) ? 0 : unzfi.crc) != UNZ_OK) {
					break;
				}

				if (unzCloseCurrentFile(szip) == UNZ_CRCERROR) {
					break;
				}
			}

			rv = unzGoToNextFile(szip);
		}

		zipClose(dzip, glob_comment.data());
		unzClose(szip);

		if (!DeleteFile(target_zip_path.c_str())) {
			LOG_WIN32_MESSAGE(GetLastError(), L"Failed to delete %s", target_zip_path.c_str());
			return 1;
		}

		if (!MoveFile(temp_name.c_str(), target_zip_path.c_str())) {
			return 1;
		}

		return 0;
	}

	int RemediateLog4JFile::ReadFileContent(const std::wstring& file_path, std::vector<BYTE>& buf, PULONG size) {
		int ret_val{};

		if (!size) {
			ret_val = 1;
		}

		// read file into buffer
		HANDLE handle_fixed_zip = CreateFile(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

		if (handle_fixed_zip == INVALID_HANDLE_VALUE) {
			LOG_MESSAGE(L"Failed to open file for read %s", file_path.c_str());
			ret_val = 1;
			goto CLEANUP;
		}

		*size = GetFileSize(handle_fixed_zip, nullptr);

		buf.resize(*size, '\0');

		if (0 == ReadFile(handle_fixed_zip, buf.data(), *size, nullptr, nullptr)) {
			ret_val = 1;
			goto CLEANUP;
		}

	CLEANUP:
		SAFE_CLOSE_HANDLE(handle_fixed_zip);
		return ret_val;
	}
}