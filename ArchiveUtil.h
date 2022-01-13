#pragma once

enum class Formats : uint8_t {
  TAR = 0,
  ZIP = 1
};

enum Compressions {
  None = 0,
  Gzip = 1,
  BZip2 = 2,
  XZ = 3
};

using archive_type_ = std::pair<Formats, Compressions>;

enum class FileTypes : uint8_t {
  Regular = 0,
  Directory = 1
};

class ArchiveBase {
protected:
  bool open_{ false };
  std::string error_str;
  archive* archive_{ nullptr };
  std::wstring archive_file_path_;
 
  virtual DWORD Open() = 0;
  virtual DWORD Close() = 0;

  virtual ~ArchiveBase() = default;

public:
  std::string getLastError() const {
    return error_str;
  }

  archive* getArchivePtr() const {
    return archive_;
  }
};

class WriterUtil final : public ArchiveBase {
public:
  explicit WriterUtil(const std::wstring& ArchiveFilePath, const archive_type_& Type);
  ~WriterUtil();

  DWORD Open() override;

  DWORD SetFormatOption(const std::string& Option, const std::string& Value);

  DWORD AddFile(const std::wstring& FilePath, const std::wstring& EntryName = L"");

  DWORD AddDirectory(const std::wstring& DirectoryName);

  DWORD AddDirectoryFromFS(const std::wstring& DirPath);

  DWORD AddEntriesFromAnotherArchive(archive* From, const std::wstring& SkipEntry = L"");

  DWORD Close() override;

private:
  int addHeader(const std::wstring& EntryName, const FileTypes EntryType, const uint64_t Size = 0, const int Permission = 0644);
  int addHeader(const std::wstring& FilePath, const std::wstring& EntryName = L"");
  int addFinish();

  archive_entry* entry_{ nullptr };

  const Formats format_;
  const Compressions compression_;
};

class ReaderUtil final : public ArchiveBase {
public:
  explicit ReaderUtil(const std::wstring& ArchiveFileName);
  ~ReaderUtil();

  DWORD Open() override;
  DWORD ExtractFileTo(const std::wstring& RootPath, const std::wstring& EntryPath = L"");
  DWORD Close() override;

private:
  bool ExtractNext(const std::wstring& RootPath, const std::wstring& EntryPath = L"");
};

class ArchiveUtil final {
public:
  static DWORD CopyArchive(const std::wstring& Source, const std::wstring& Destination, const archive_type_& Type, const std::wstring& SkipEntry = L"");
  static DWORD RemoveFile(const std::wstring& Source, const std::wstring& EntryPath, const archive_type_& Type);
  static DWORD ExtractFile(const std::wstring& Source, const std::wstring& ToPath, const std::wstring& EntryPath);
  static DWORD ReplaceEntry(const std::wstring& ArchivePath, const std::wstring& EntryPath, const std::wstring& FilePath, const archive_type_& Type);
  static bool GetFormatAndArchiveType(const std::wstring& Path, std::pair<Formats, Compressions>& ArchiveType);
};