#pragma once

// Including SDKDDKVer.h defines the highest available Windows platform.

// If you wish to build your application for a previous Windows platform, include WinSDKVer.h and
// set the _WIN32_WINNT macro to the platform you wish to support before including SDKDDKVer.h.

#include <winsdkver.h>

//
// Target Windows XP SP3 with Internet Explorer 5.01
// Use of any newer API(s) should use LoadLibrary()/GetProcAddress()
//
#ifndef WINVER
#define WINVER 0x0501
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#ifndef _WIN32_WINDOWS
#define _WIN32_WINDOWS 0x0501
#endif
#ifndef _WIN32_IE
#define _WIN32_IE 0x0501
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x05010300
#endif

#include <SDKDDKVer.h>

// Newly defined versions of Windows

#ifndef _WIN32_WINNT_WIN8
#define _WIN32_WINNT_WIN8                   0x0602
#endif
#ifndef _WIN32_WINNT_WINBLUE
#define _WIN32_WINNT_WINBLUE                0x0603
#endif
#ifndef NTDDI_WIN8
#define NTDDI_WIN8                          0x06020000
#endif
#ifndef NTDDI_WINBLUE
#define NTDDI_WINBLUE                       0x06030000
#endif

