
#include "stdafx.h"
#include "Reports.h"
#include "Remediate.h"
#include "Utils.h"
#include "ArchiveUtil.h"

namespace log4jremediate {
	const std::wregex line1_regex(L"Source: Manifest Vendor: ([^,]*), Manifest Version: ([^,]*), JNDI Class: ([^,]*), Log4j Vendor: ([^,]*), Log4j Version: ([^,]*)");
	const std::wregex line2_regex(L"Path=(.*)");


	DWORD ExtractFileArchives(const std::vector<std::wstring>& archives, PairStack& archives_mapping, std::unordered_set<std::wstring>& tempLocset) {
		if (archives.empty()) {
			return ERROR_INVALID_PARAMETER;
		}

		DWORD err_code{ ERROR_SUCCESS };
		std::wstring tmp_path;
		std::wstring current_file{ archives.at(0) };

		for (size_t i = 1; i < archives.size(); i++) {
			tmp_path = GetTempFilePath();
			if (tmp_path.empty()) {
				err_code = ERROR_FUNCTION_FAILED;
				break;
			}

			err_code = ArchiveUtil::ExtractFile(current_file, tmp_path, archives[i]);
			if (err_code == ERROR_SUCCESS) {
				archives_mapping.emplace(archives[i], tmp_path);
				tempLocset.emplace(tmp_path);
				current_file = tmp_path;
			}
			else {
				LOG_MESSAGE(L"Failed to locate file: %s", archives[i].c_str());
				break;
			}
		}

		return err_code;
	}

	void log4jremediate::RemediateLog4JFile::CleanupTempFiles(const std::unordered_set<std::wstring>& setTempLocs) {
		for (const auto& filename : setTempLocs) {
			if ((GetFileAttributes(filename.c_str()) != INVALID_FILE_ATTRIBUTES) && !DeleteFile(filename.c_str())) {
					LogStatusMessage(L"Fail to delete %s; Win32 error: %d\n", filename.c_str(), GetLastError());
			}
		}
	}

	DWORD ReadSignatureReport(const std::wstring& report, std::vector<CReportVulnerabilities>& result) {
		DWORD status{ ERROR_SUCCESS };
		std::wstringstream wss;
		std::wifstream wif;
		std::vector<std::wstring> lines;

		// If we are unable to fetch File Attributes, it simply means file doesn't exist
		if (GetFileAttributes(report.c_str()) == INVALID_FILE_ATTRIBUTES) {
			LOG_MESSAGE(L"Signature report %s not found.", report.c_str());
			goto END;
		}

		//Read the content
		wif.open(report, std::ios::in);

		if (!wif.is_open()) {
			status = ERROR_OPEN_FAILED;
			LOG_WIN32_MESSAGE(status, L"Failed to open signature report %s", report.c_str());
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
						(wsm1[3].str() == L"Found"), false, wsm1[5].str(), wsm1[4].str(), false, false, false, false, false, L"");
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

		std::wstring sig_report_file{ GetSignatureReportFindingsFilename() };

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
    
		try {
			sig_report_file = GetSignatureReportFindingsFilename();
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

				if (IsCVE202144228Mitigated(W2A(vuln.log4jVendor), vuln.detectedJNDILookupClass, W2A(vuln.log4jVersion)) &&
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
			LOG_WIN32_MESSAGE(status, L"Failed to allocate memory in %S", __func__);
		}
		catch (std::exception& e) {
			status = ERROR_INVALID_OPERATION;
			LOG_WIN32_MESSAGE(status, L"Exception %S caught in %S", e.what(), __func__);
		}

	END:

		return (report_status != ERROR_SUCCESS ? report_status : status);
	}

	DWORD RemediateLog4JFile::RemediateFileArchive(const std::wstring& vulnerable_file_path) {
		DWORD status{ ERROR_SUCCESS };
		PairStack archives_mapping;
		std::vector<std::wstring> result;
		std::unordered_set<std::wstring> setTempLocs;
		std::wstring tmp_path;
		PACL pOldDACL{ nullptr };
		PSID psidGroup{ nullptr };
		PSID psidOwner{ nullptr };
		PSECURITY_DESCRIPTOR pSD{ nullptr };
		DWORD fileAttr{};

		try {
			SplitWideString(vulnerable_file_path, L"!", result);

			if (result.empty()) {
				status = ERROR_INVALID_DATA;
				LOG_WIN32_MESSAGE(status, L"No file path found in %s", vulnerable_file_path.c_str());
				goto END;
			}

			// If we are unable to fetch File Attributes, it simply means file doesn't exist
			fileAttr = GetFileAttributes(result[0].c_str());

			if (fileAttr == INVALID_FILE_ATTRIBUTES) {
				status = ERROR_FILE_NOT_FOUND;
				LOG_WIN32_MESSAGE(status, L"Failed to fix %s because file not found", result[0].c_str());
				goto END;
			}
			
			// check if file is read only then do not process the archive
			if (fileAttr & FILE_ATTRIBUTE_READONLY) {
				status = ERROR_ACCESS_DENIED;
				LOG_WIN32_MESSAGE(status, L"Failed to fix %s because it is read only", result[0].c_str());
				goto END;
			}

			if (GetNamedSecurityInfo(result[0].c_str(),
				SE_FILE_OBJECT,
				GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
				&psidOwner,
				&psidGroup,
				&pOldDACL,
				nullptr,
				&pSD) != ERROR_SUCCESS
				) {
				status = GetLastError();
				LOG_WIN32_MESSAGE(status, L"Failed to get permissions of file %s", result[0].c_str());
				goto END;
			}

			tmp_path = GetTempFilePath();

			if (tmp_path.empty()) {
				status = ERROR_FUNCTION_FAILED;
				goto END;
			}

			if (FALSE == CopyFile(result[0].c_str(), tmp_path.c_str(), FALSE)) {
				status = GetLastError();
				LOG_WIN32_MESSAGE(status, L"Failed to copy %s to %s", result[0].c_str(), tmp_path.c_str());
				goto END;
			}			

			// Map outermost file with corresponding temp file
			archives_mapping.emplace(result[0], tmp_path);

			//Add to set of delete files
			setTempLocs.emplace(tmp_path);

			if (ExtractFileArchives(result, archives_mapping, setTempLocs)) {
				status = ERROR_INVALID_OPERATION;
				LOG_WIN32_MESSAGE(status, L"Failed to extract file archives from %s", vulnerable_file_path.c_str());
				goto END;
			}

			// Pop the stack and fix topmost jar.
			auto last_visited = archives_mapping.top();
			archives_mapping.pop();

			archive_type_ type;
			if (!ArchiveUtil::GetFormatAndArchiveType(last_visited.first, type)) {
				status = ERROR_FUNCTION_FAILED;
				goto END;
			}

			status = ArchiveUtil::RemoveFile(last_visited.second.c_str(), L"org/apache/logging/log4j/core/lookup/JndiLookup.class", type);
			if (status != ERROR_SUCCESS) {
				LOG_WIN32_MESSAGE(status, L"Failed to delete JndiLookup.class from archive: %s", last_visited.second.c_str());
				goto END;
			}

			while (!archives_mapping.empty()) {
				auto parent_jar_mapping = archives_mapping.top();
				archives_mapping.pop();

				if (!ArchiveUtil::GetFormatAndArchiveType(parent_jar_mapping.first, type)) {
					status = ERROR_FUNCTION_FAILED;
					goto END;
				}

				if (ArchiveUtil::ReplaceEntry(parent_jar_mapping.second, last_visited.first, last_visited.second, type)) {
					status = ERROR_INVALID_OPERATION;
					LOG_WIN32_MESSAGE(status, L"Failed to repackage fixed %s into %s", last_visited.first.c_str(), parent_jar_mapping.second.c_str());
					goto END;
				}

				last_visited = parent_jar_mapping;
			}

			// Make backup of original jar
			auto original_backup = result[0] + L".backup";
			if (!MoveFile(result[0].c_str(), original_backup.c_str())) {
				status = GetLastError();
				LOG_WIN32_MESSAGE(status, L"Failed to rename %s to %s", result[0].c_str(), original_backup.c_str());
				goto END;
			}

			// Add backup file to the set of delete files 
			setTempLocs.emplace(original_backup);

			// replace fixed jar with original
			if (!MoveFile(tmp_path.c_str(), result[0].c_str())) {
				status = GetLastError();
				LOG_WIN32_MESSAGE(status, L"Failed to rename %s to %s", tmp_path.c_str(), result[0].c_str());
				goto END;
			}

			WCHAR file_path[MAX_PATH] = { '\0' };
			wcscpy_s(file_path, result[0].c_str());

			if (SetNamedSecurityInfo(file_path, 
				SE_FILE_OBJECT,
				GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
				psidOwner, 
				psidGroup, 
				pOldDACL, 
				nullptr) != ERROR_SUCCESS
				) {
				status = GetLastError();
				LOG_WIN32_MESSAGE(status, L"Failed to set permissions to file %s", result[0].c_str());
				goto END;
			}
			
			LOG_MESSAGE("Copied fixed file: %s", result[0].c_str());

			// Delete temporary files
			CleanupTempFiles(setTempLocs);			
		}
		catch (std::bad_alloc&) {
			status = ERROR_OUTOFMEMORY;
			LOG_WIN32_MESSAGE(status, L"Failed to allocate memory in %S", __func__);
			goto END;
		}
		catch (std::exception& e) {
			status = ERROR_INVALID_OPERATION;
			LOG_WIN32_MESSAGE(status, L"Exception %S caught in %S", e.what(), __func__);
			goto END;
		}		

	END:

		if (pSD != nullptr) {
			LocalFree((HLOCAL)pSD);
		}

		return status;
	}
}