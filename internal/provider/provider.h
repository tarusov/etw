// +build windows
// +build !winxp

#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0700 // Windows7+

#include <windows.h>
#include <tdh.h>
#include <wchar.h>
#include <stdio.h>

// ETW_PROVIDER_INFO holds provider name and guid.
typedef struct {
  GUID    ProviderGuid;
  LPWSTR  ProviderName;
} ETW_PROVIDER_INFO;

typedef struct {
  LPWSTR    Name;
  ULONGLONG Value;
} ETW_KEYWORD_INFO;

// EnumerateProviders returns a mapping of provider name to guid.
DWORD EnumerateProviders(ETW_PROVIDER_INFO *providers, DWORD *count);

// EnumerateProviderKeywords returns provider keywords.
DWORD EnumerateProviderKeywords(LPGUID pGuid, ETW_KEYWORD_INFO *keywords, ULONG *count);
