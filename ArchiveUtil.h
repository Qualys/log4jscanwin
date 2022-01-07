#pragma once

enum class Formats : uint8_t {
  TAR = 0,
  ZIP = 1
};

enum Compressions {
  None = 0,
  Gzip = 1
};

enum class FileTypes : uint8_t {
  Regular = 0,
  Directory = 1
};

class ArchiveUtil {
public:
  bool open_{ false };
  std::string error_str;
  archive* archive_{ nullptr };
  std::wstring archive_file_path_;

  virtual DWORD Open() = 0;
  virtual DWORD Close() = 0;

  virtual ~ArchiveUtil() = default;
};

class WriterUtil final : protected ArchiveUtil {
public:
  explicit WriterUtil(const std::wstring& ArchiveFilePath, const Formats& Format, const Compressions& Compression);
  ~WriterUtil();

  DWORD Open() override;

  DWORD SetFormatOption(const std::string& Option, const std::string& Value);

  DWORD AddFile(const std::wstring& FilePath, const std::wstring& EntryName = L"");

  DWORD AddDirectory(const std::wstring& DirectoryName);

  DWORD AddDirectoryFromFS(const std::wstring& DirPath);

  DWORD Close() override;

private:
  int addHeader(const std::wstring& EntryName, const FileTypes EntryType, const uint64_t Size = 0, const int Permission = 0644);
  int addHeader(const std::wstring& FilePath, const std::wstring& EntryName = L"");
  int addFinish();

  archive_entry* entry_{ nullptr };

  const Formats format_;
  const Compressions compression_;
};

class ReaderUtil final : protected ArchiveUtil {
public:
  explicit ReaderUtil(const std::wstring& ArchiveFileName);
  ~ReaderUtil();

  DWORD Open() override;
  DWORD ExtractFileTo(const std::wstring& RootPath);

private:
  bool ExtractNext(const std::wstring& RootPath);
  DWORD Close() override;
};