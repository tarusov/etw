// +build windows

package winapi

/*
#include <windows.h>
#include <wchar.h>
*/
import "C"
import (
	"unicode/utf16"
	"unsafe"
)

// LPWSTR is pointer to wide-char unicode string.
type LPWSTR C.LPWSTR

// DecodeLPWSTR converts C.LPWSTR to go string.
func DecodeLPWSTR(val LPWSTR) string {
	const maxRunes = 1<<30 - 1

	var (
		valPtr  = unsafe.Pointer(val)
		valLen  = C.wcslen((*C.wchar_t)(valPtr))
		wideStr = (*[maxRunes]uint16)(valPtr)[:valLen:valLen]
	)

	return string(utf16.Decode(wideStr))
}
