// +build windows

package winapi

/*
#include <windows.h>

char* getLastErrorString() {
	DWORD dwErr = GetLastError();
	LPSTR lpszMsgBuf;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, 0, dwErr, 0, (LPSTR)&lpszMsgBuf, 0, NULL);
	return (char *)lpszMsgBuf;
}
*/
import "C"
import "errors"

// GetLastError returns last windows handler error.
func GetLastError() error {
	var errStr = C.getLastErrorString()
	err := errors.New(C.GoString(errStr))
	C.LocalFree(C.HLOCAL(errStr))

	return err
}
