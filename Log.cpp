#include "stdafx.h"
#include "Log.h"

// Returns the wide string for given Win32 error code
std::wstring GetWin32ErrorAsString(const DWORD& error_code) {
	LPWSTR messageBuffer = nullptr;
  
	if (error_code == ERROR_SUCCESS) {
		return std::wstring();
	}
  
	size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    nullptr , error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, nullptr);
  
	std::wstring message(messageBuffer, size);
  
	LocalFree(messageBuffer);

	return message;
}
