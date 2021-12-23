#pragma once

constexpr DWORD BUFFER_READ_SIZE = 256;
constexpr DWORD SIGNATURE_ITEM_LENGTH = 4;

bool RemediateFromSignatureReport();
bool RemediateFile(const std::wstring& file);
