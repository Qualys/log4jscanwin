#include "stdafx.h"
#include "Utils.h"
#include "ArchiveUtil.h"

int (*format_tab[])(archive*) = { 
  archive_write_set_format_gnutar, 
  archive_write_set_format_zip 
};

int (*compression_tab[])(archive*) = { 
  archive_write_set_compression_none, 
  archive_write_set_compression_gzip,
  archive_write_set_compression_bzip2,
  archive_write_set_compression_xz
};

constexpr int archive_file_type[] = { 
  AE_IFREG, 
  AE_IFDIR 
};

WriterUtil::WriterUtil(const std::wstring& ArchiveFilePath, const archive_type_& Type) : format_(Type.first), compression_(Type.second) {
  archive_file_path_ = ArchiveFilePath;
}

DWORD WriterUtil::Open() {
  DWORD err_code{ ERROR_SUCCESS };
  int archive_err{ ARCHIVE_OK };

  archive_ = archive_write_new();
  if (!archive_) {
    err_code = ERROR_INVALID_HANDLE;
    goto CLEANUP;
  }

  entry_ = archive_entry_new();
  if (!entry_) {
    err_code = ERROR_INVALID_HANDLE;
    goto CLEANUP;
  }

  archive_err = format_tab[static_cast<uint8_t>(format_)](archive_);

  if (archive_err != ARCHIVE_OK) {
    error_str = archive_error_string(archive_);
    err_code = ERROR_FUNCTION_FAILED;
    goto CLEANUP;
  }

  archive_err = compression_tab[compression_](archive_);

  if (archive_err != ARCHIVE_OK) {
    error_str = archive_error_string(archive_);
    err_code = ERROR_FUNCTION_FAILED;
    goto CLEANUP;
  }

  archive_err = archive_write_open_filename_w(archive_, archive_file_path_.c_str());
  if (archive_err != ARCHIVE_OK) {
    error_str = archive_error_string(archive_);
    err_code = ERROR_FILE_INVALID;
    goto CLEANUP;
  }

  open_ = true;

CLEANUP:

  return err_code;
}

WriterUtil::~WriterUtil() {
  Close();
}

DWORD WriterUtil::SetFormatOption(const std::string& Option, const std::string& Value) {
  if (archive_write_set_format_option(archive_, nullptr, Option.c_str(), Value.c_str()) != ARCHIVE_OK) {
    error_str = archive_error_string(archive_);
    return ERROR_FUNCTION_FAILED;
  }

  return ERROR_SUCCESS;
}

int WriterUtil::addHeader(const std::wstring& EntryName, const FileTypes EntryType, const uint64_t Size, const int Permission) {
  if (entry_) {
    entry_ = archive_entry_clear(entry_);
    archive_entry_copy_pathname_w(entry_, EntryName.c_str());
    archive_entry_set_perm(entry_, Permission);
    archive_entry_set_filetype(entry_, archive_file_type[static_cast<uint8_t>(EntryType)]);
    archive_entry_set_size(entry_, Size);
    return archive_write_header(archive_, entry_);
  }

  return ARCHIVE_FAILED;
}

int WriterUtil::addHeader(const std::wstring& FilePath, const std::wstring& EntryName) {
  int err_code{ ARCHIVE_FAILED };
  archive* archive_local{ nullptr };

  if (entry_) {
    archive_local = archive_read_disk_new();

    if (!archive_local) {
      error_str = archive_error_string(archive_);
      goto CLEANUP;
    }

    entry_ = archive_entry_clear(entry_);
    archive_entry_copy_pathname_w(entry_, EntryName.c_str());
    archive_entry_copy_sourcepath_w(entry_, FilePath.c_str());

    err_code = archive_read_disk_entry_from_file(archive_local, entry_, -1, 0);

    if (err_code != ARCHIVE_OK) {
      error_str = archive_error_string(archive_);
      goto CLEANUP;
    }
    else {
      err_code = archive_write_header(archive_, entry_);
      if (err_code != ARCHIVE_OK) {
        error_str = archive_error_string(archive_);
      }
    }
  }

CLEANUP:

  if (archive_local) {
    archive_read_close(archive_local);
    archive_read_free(archive_local);
  }

  return err_code;
}

int WriterUtil::addFinish() {
  return archive_write_finish_entry(archive_);
}

DWORD WriterUtil::AddFile(const std::wstring& FilePath, const std::wstring& EntryName) {
  DWORD err_code{ ERROR_SUCCESS };
  DWORD file_attrib{ GetFileAttributes(FilePath.c_str()) };

  if (file_attrib == INVALID_FILE_ATTRIBUTES || (file_attrib & FILE_ATTRIBUTE_DIRECTORY)) {
    err_code = ERROR_FILE_INVALID;
    goto CLEANUP;
  }

  if (addHeader(FilePath, EntryName.empty() ? FilePath : EntryName) != ARCHIVE_OK) {
    err_code = ERROR_FUNCTION_FAILED;
    goto CLEANUP;
  }

  {
    std::vector<char> buff(8192);
    std::fstream entry_file(FilePath.c_str(), std::ios::in | std::ios::binary);

    if (!entry_file) {
      err_code = ERROR_OPEN_FAILED;
      goto CLEANUP;
    }

    while (entry_file.good()) {
      buff.clear();
      entry_file.read(buff.data(), 8192);
      if (archive_write_data(archive_, buff.data(), static_cast<size_t>(entry_file.gcount())) == -1) {
        err_code = ERROR_WRITE_FAULT;
        break;
      }
    }

    entry_file.close();
  }

CLEANUP:

  addFinish();

  return err_code;
}

DWORD WriterUtil::AddDirectory(const std::wstring& DirectoryName) {
  DWORD err_code{ ERROR_SUCCESS };

  if (addHeader(DirectoryName, FileTypes::Directory, 0, 0777) != ARCHIVE_OK) {
    err_code = ERROR_FUNCTION_FAILED;
  }

  addFinish();

  return err_code;
}

DWORD WriterUtil::AddDirectoryFromFS(const std::wstring& DirPath) {
  DWORD error{ ERROR_SUCCESS };
  WIN32_FIND_DATA FindFileData{};
  HANDLE hFind{ INVALID_HANDLE_VALUE };
  std::stack<std::wstring> dirs;
  std::wstring current_path;

  dirs.push(DirPath.back() == L'\\' ? DirPath : DirPath + L"\\");

  while (!dirs.empty()) {
    current_path = dirs.top();
    dirs.pop();

    hFind = FindFirstFile(std::wstring(current_path + L"\\*").c_str(), &FindFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
      do {
        if (!std::wcscmp(FindFileData.cFileName, L".") ||
            !std::wcscmp(FindFileData.cFileName, L"..") ||
          (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == FILE_ATTRIBUTE_REPARSE_POINT ||
          (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) == FILE_ATTRIBUTE_DEVICE ||
          (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_OFFLINE) == FILE_ATTRIBUTE_OFFLINE ||
          (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_TEMPORARY) == FILE_ATTRIBUTE_TEMPORARY ||
          (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_VIRTUAL) == FILE_ATTRIBUTE_VIRTUAL) {
          continue;
        }

        std::wstring temp_path{ current_path + FindFileData.cFileName };

        if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY) {
          dirs.push(temp_path + L"\\");
          AddDirectory(temp_path.substr(DirPath.length() + 1));
        }
        else {
          AddFile(temp_path, temp_path.substr(DirPath.length() + 1));
        }

      } while (FindNextFile(hFind, &FindFileData));

      FindClose(hFind);
      hFind = INVALID_HANDLE_VALUE;
    }
    else {
      error = GetLastError();
    }
  }

  return error;
  
}

DWORD WriterUtil::AddEntriesFromAnotherArchive(archive* From, const std::wstring& SkipEntry) {
  int archive_err{ ARCHIVE_OK };
  archive_entry* entry_local{ nullptr };

  auto CopyEntry = [](archive* ar, archive* aw) -> int {
    int archive_err_local{ ARCHIVE_OK };
    const void* buff{ nullptr };
    size_t size{ 0 };
    la_int64_t offset{ 0 };

    while (true) {
      archive_err_local = archive_read_data_block(ar, &buff, &size, &offset);

      if (archive_err_local == ARCHIVE_EOF) {
        return ARCHIVE_OK;
      }

      if (archive_err_local != ARCHIVE_OK) {
        return archive_err_local;
      }

      if (archive_write_data(aw, buff, size) == -1) {
        return ARCHIVE_FAILED;
      }
    }
  };

  while (true) {
    int needcr = 0;
    archive_err = archive_read_next_header(From, &entry_local);

    if (archive_err != ARCHIVE_EOF && archive_err != ARCHIVE_OK) {
      error_str = archive_error_string(From);
      break;
    }

    if (archive_err == ARCHIVE_EOF) {
      break;
    }

    if (!SkipEntry.empty() && _wcsicmp(SkipEntry.c_str(), archive_entry_pathname_w(entry_local)) == 0) {
      continue;
    }

    archive_err = archive_write_header(archive_, entry_local);
    if (archive_err != ARCHIVE_OK) {
      error_str = archive_error_string(archive_);
      break;
    }

    if (archive_entry_size(entry_local) > 0) {
      archive_err = CopyEntry(From, archive_);
      if (archive_err != ARCHIVE_OK) {
        error_str = archive_error_string(archive_);
        break;
      }
    }
  }

  return (archive_err == ARCHIVE_EOF ? ERROR_SUCCESS : ERROR_FUNCTION_FAILED);
}

DWORD WriterUtil::Close() {
  if (open_) {
    if (archive_) {
      archive_write_close(archive_);
      archive_write_free(archive_);
    }

    if (entry_) {
      archive_entry_free(entry_);
    }

    open_ = false;
  }

  return ERROR_SUCCESS;
}

ReaderUtil::ReaderUtil(const std::wstring& ArchiveFileName) {
  archive_file_path_ = ArchiveFileName;
}

DWORD ReaderUtil::Open() {
  DWORD err_code{ ERROR_SUCCESS };
  int archive_err{ ARCHIVE_OK };

  DWORD file_attrib = GetFileAttributes(archive_file_path_.c_str());

  if (file_attrib == INVALID_FILE_ATTRIBUTES || (file_attrib & FILE_ATTRIBUTE_DIRECTORY)) {
    err_code = ERROR_FILE_INVALID;
    goto CLEANUP;
  }

  archive_ = archive_read_new();
  if (!archive_) {
    err_code = ERROR_INVALID_HANDLE;
    goto CLEANUP;
  }

  archive_err = archive_read_support_format_all(archive_);

  if (archive_err != ARCHIVE_OK) {
    error_str = archive_error_string(archive_);
    err_code = ERROR_FUNCTION_FAILED;
    goto CLEANUP;
  }

  archive_err = archive_read_support_compression_all(archive_);
  if (archive_err != ARCHIVE_OK) {
    error_str = archive_error_string(archive_);
    err_code = ERROR_FUNCTION_FAILED;
    goto CLEANUP;
  }

  archive_err = archive_read_open_filename_w(archive_, archive_file_path_.c_str(), 10240);
  if (archive_err != ARCHIVE_OK) {
    error_str = archive_error_string(archive_);
    err_code = ERROR_OPEN_FAILED;
    goto CLEANUP;
  }

  open_ = true;

CLEANUP:
  return err_code;
}

DWORD ReaderUtil::ExtractFileTo(const std::wstring& RootPath, const std::wstring& EntryPath) {
  DWORD err_code{ ERROR_SUCCESS };

  while (true) {
    if (!ExtractNext(RootPath, EntryPath)) {
      err_code = GetLastError();

      if (err_code == ERROR_HANDLE_EOF) {
        err_code = ERROR_SUCCESS;
        break;
      }
      else {
        break;
      }
    }
  }

  return err_code;
}

ReaderUtil::~ReaderUtil() {
  Close();
}

bool ReaderUtil::ExtractNext(const std::wstring& RootPath, const std::wstring& EntryPath) {
  archive_entry* entry{ nullptr };
  bool ret_val{ false };
  int archive_err{ ARCHIVE_OK };
  const wchar_t* entry_path{ nullptr };
  archive* archive_local = archive_write_disk_new();

  auto CopyData = [](archive* ar, archive* aw) -> int {
    int archive_err{ ARCHIVE_OK };
    const void* buff{ nullptr };
    size_t size{ 0 };
    la_int64_t offset{ 0 };

    while (true) {
      archive_err = archive_read_data_block(ar, &buff, &size, &offset);

      if (archive_err == ARCHIVE_EOF) {
        return ARCHIVE_OK;
      }

      if (archive_err != ARCHIVE_OK) {
        return archive_err;
      }

      archive_err = static_cast<int>(archive_write_data_block(aw, buff, size, offset));

      if (archive_err != ARCHIVE_OK) {
        return archive_err;
      }
    }
  };

  if (!archive_local) {
    SetLastError(ERROR_INVALID_HANDLE);
    goto CLEANUP;
  }

  archive_err = archive_write_disk_set_options(archive_local,
    ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS | ARCHIVE_EXTRACT_OWNER);

  if (archive_err != ARCHIVE_OK) {
    error_str = archive_error_string(archive_);
    SetLastError(ERROR_FUNCTION_FAILED);
    goto CLEANUP;
  }

  archive_err = archive_write_disk_set_standard_lookup(archive_local);

  if (archive_err != ARCHIVE_OK) {
    error_str = archive_error_string(archive_);
    SetLastError(ERROR_FUNCTION_FAILED);
    goto CLEANUP;
  }

  archive_err = archive_read_next_header(archive_, &entry);

  if (archive_err != ARCHIVE_EOF && archive_err != ARCHIVE_OK) {
    error_str = archive_error_string(archive_);
    SetLastError(ERROR_FUNCTION_FAILED);
    goto CLEANUP;
  }

  if (archive_err == ARCHIVE_EOF) {
    SetLastError(ERROR_HANDLE_EOF);
    goto CLEANUP;
  }

  entry_path = archive_entry_pathname_w(entry);

  if (!EntryPath.empty()) {
    if (_wcsicmp(EntryPath.c_str(), entry_path) != 0) {
      ret_val = true;
      goto CLEANUP;
    }

    archive_entry_copy_pathname_w(entry, RootPath.c_str());
  }
  else {
    archive_entry_copy_pathname_w(entry, (RootPath + L"\\" + entry_path).c_str());
  }

  archive_err = archive_write_header(archive_local, entry);
  if (archive_err != ARCHIVE_OK) {
    error_str = archive_error_string(archive_local);
    SetLastError(ERROR_FUNCTION_FAILED);
    goto CLEANUP;
  }

  if (archive_entry_size(entry) > 0) {
    archive_err = CopyData(archive_, archive_local);
    if (archive_err != ARCHIVE_OK) {
      error_str = archive_error_string(archive_local);
      SetLastError(ERROR_FUNCTION_FAILED);
      goto CLEANUP;
    }
  }

  ret_val = true;

CLEANUP:

  if (archive_local) {
    archive_write_finish_entry(archive_local);
    archive_write_close(archive_local);
    archive_write_free(archive_local);
  }

  return ret_val;
}

DWORD ReaderUtil::Close() {
  if (open_) {
    if (archive_) {
      archive_read_close(archive_);
      archive_read_free(archive_);
    }

    open_ = false;
  }

  return ERROR_SUCCESS;
}

DWORD ArchiveUtil::CopyArchive(const std::wstring& Source, const std::wstring& Destination, 
  const archive_type_& Type, const std::wstring& SkipEntry) {
  DWORD err_code{ ERROR_SUCCESS };
  WriterUtil writer(Destination, Type);
  ReaderUtil reader(Source);

  err_code = writer.Open();
  if (err_code != ERROR_SUCCESS) {
    goto END;
  }

  err_code = reader.Open();
  if (err_code != ERROR_SUCCESS) {
    goto END;
  }

  err_code = writer.AddEntriesFromAnotherArchive(reader.getArchivePtr(), SkipEntry);
  if (err_code != ERROR_SUCCESS) {
    goto END;
  }

END:

  return err_code;
}

DWORD ArchiveUtil::RemoveFile(const std::wstring& Source, const std::wstring& EntryPath, const archive_type_& Type) {
  DWORD err_code{ ERROR_SUCCESS };
  std::wstring tmp_path{ GetTempFilePath() };

  if (tmp_path.empty()) {
    return ERROR_FUNCTION_FAILED;
  }

  err_code = CopyArchive(Source, tmp_path, Type, EntryPath);

  if (err_code != ERROR_SUCCESS) {
    goto END;
  }

  if (!MoveFileEx(tmp_path.c_str(), Source.c_str(), MOVEFILE_REPLACE_EXISTING)) {
    err_code = GetLastError();
    goto END;
  }

END:

  if (err_code != ERROR_SUCCESS) {
    DeleteFile(tmp_path.c_str());
  }

  return err_code;
}

DWORD ArchiveUtil::ExtractFile(const std::wstring& Source, const std::wstring& ToPath, const std::wstring& EntryPath) {
  if (EntryPath.empty() || ToPath.empty() || Source.empty()) {
    return ERROR_INVALID_PARAMETER;
  }
  
  DWORD err_code{ ERROR_SUCCESS };
  ReaderUtil reader(Source);

  err_code = reader.Open();
  if (err_code != ERROR_SUCCESS) {
    goto END;
  }

  err_code = reader.ExtractFileTo(ToPath, EntryPath);
  if (err_code != ERROR_SUCCESS) {
    goto END;
  }

END:
  return err_code;
}

DWORD ArchiveUtil::ReplaceEntry(const std::wstring& ArchivePath, const std::wstring& EntryPath, const std::wstring& FilePath, const archive_type_& Type) {
  DWORD err_code{ ERROR_SUCCESS };
  std::wstring tmp_path{ GetTempFilePath() };

  if (tmp_path.empty()) {
    return ERROR_FUNCTION_FAILED;
  }

  WriterUtil writer(tmp_path, Type);
  ReaderUtil reader(ArchivePath.data());

  err_code = writer.Open();
  if (err_code != ERROR_SUCCESS) {
    goto END;
  }

  err_code = reader.Open();
  if (err_code != ERROR_SUCCESS) {
    goto END;
  }

  err_code = writer.AddEntriesFromAnotherArchive(reader.getArchivePtr(), EntryPath);
  if (err_code != ERROR_SUCCESS) {
    goto END;
  }

  err_code = writer.AddFile(FilePath, EntryPath);
  if (err_code != ERROR_SUCCESS) {
    goto END;
  }

  writer.Close();
  reader.Close();

  if (!MoveFileEx(tmp_path.c_str(), ArchivePath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
    err_code = GetLastError();
    goto END;
  }

END:

  if (err_code != ERROR_SUCCESS) {
    DeleteFile(tmp_path.c_str());
  }

  return err_code;
}

bool ArchiveUtil::GetFormatAndArchiveType(const std::wstring& Path, std::pair<Formats, Compressions>& ArchiveType) {
  if (IsKnownFileExtension(knownZipExtensions, Path)) {
    ArchiveType = std::make_pair(Formats::ZIP, Compressions::None);
    return true;
  }

  if (IsKnownFileExtension(knownBZipTarExtensions, Path)) {
    ArchiveType = std::make_pair(Formats::TAR, Compressions::BZip2);
    return true;
  }

  if (IsKnownFileExtension(knownGZipTarExtensions, Path)) {
    ArchiveType = std::make_pair(Formats::TAR, Compressions::Gzip);
    return true;
  }

  if (IsKnownFileExtension(knownTarExtensions, Path)) {
    ArchiveType = std::make_pair(Formats::TAR, Compressions::None);
    return true;
  }

  return false;
}
