#pragma once

std::wstring GetWin32ErrorAsString(const DWORD& error_code);

#define LOG_MESSAGE(message, ...) LogStatusMessage(message L"\n", __VA_ARGS__)

#define LOG_WIN32_MESSAGE(error_code, message, ...) LOG_MESSAGE(message L": %s", __VA_ARGS__, GetWin32ErrorAsString(error_code).c_str())