// +build windows
// +build !winxp

package provider

/*
#cgo LDFLAGS: -l tdh
#include "provider.h"
*/
import "C"
import (
	"strings"
	"unsafe"

	"github.com/tarusov/etw/internal/winapi"
)

// EnumerateProviders returns a mapping of provider name to guid.
//
// For enumerating providers by a command line use:
// `logman query providers "Windows Kernel Trace"`.
func EnumerateProviders() (map[string]GUID, error) {

	const bufSize = 0x800

	// providerInfo is a Go-copy of C ETW_PROVIDER_INFO. See: provider.h.
	type providerInfo struct {
		GUID GUID
		Name winapi.LPWSTR
	}

	var (
		providers    = make([]providerInfo, bufSize)
		providersPtr = unsafe.Pointer(&providers[0])

		count    uint32
		countPtr = unsafe.Pointer(&count)
	)

	var result = C.EnumerateProviders(
		(*C.ETW_PROVIDER_INFO)(providersPtr),
		(*C.DWORD)(countPtr),
	)
	if result != C.ERROR_SUCCESS {
		return nil, winapi.GetLastError()
	}

	var nameToGUID = make(map[string]GUID, count)
	for i := uint32(0); i < count; i++ {
		var lpwProviderName = winapi.LPWSTR(unsafe.Pointer(providers[i].Name))
		var providerName = winapi.DecodeLPWSTR(lpwProviderName)
		C.free(unsafe.Pointer(lpwProviderName))

		nameToGUID[strings.ToLower(providerName)] = providers[i].GUID
	}

	return nameToGUID, nil
}

// EnumerateProviderKeywords returns a mapping of a keyword name to a keyword
// value.
//
// For listing keywords (for "Windows Kernel Trace" provider) by a command line
// use: `logman query providers "Windows Kernel Trace"`.
func EnumerateProviderKeywords(providerGUID GUID) (map[string]uint64, error) {

	const bufSize = 0x800

	type keywordInfo struct {
		Name  winapi.ULONGLONG // Keyword name pointer.
		Value uint64           // Keyword flag value.
	}

	var (
		keywords    = make([]keywordInfo, bufSize) // keywordInfo struct data depends from arch type.
		keywordsPtr = unsafe.Pointer(&keywords[0])

		count    uint32
		countPtr = unsafe.Pointer(&count)
	)

	var result = C.EnumerateProviderKeywords(
		C.LPGUID(unsafe.Pointer(&providerGUID)),
		(*C.ETW_KEYWORD_INFO)(keywordsPtr),
		(*C.DWORD)(countPtr),
	)
	if result != C.ERROR_SUCCESS {
		// No keywords founded for target provider.
		if result == C.ERROR_FILE_NOT_FOUND ||
			result == C.ERROR_NOT_FOUND ||
			result == C.ERROR_MUI_FILE_NOT_FOUND {
			return make(map[string]uint64, 0), nil
		}

		return nil, winapi.GetLastError()
	}

	var keywordValues = make(map[string]uint64, count)
	for i := uint32(0); i < count; i++ {
		var lpwName = winapi.LPWSTR(keywords[i].Name.Pointer)
		var name = winapi.DecodeLPWSTR(lpwName)
		C.free(unsafe.Pointer(lpwName))

		keywordValues[name] = keywords[i].Value
	}

	return keywordValues, nil
}
