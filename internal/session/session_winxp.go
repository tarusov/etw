// +build windows
// +build winxp

package session

/*
#include "session_winxp.h"
*/
import "C"
import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (s *EtwSession) subscribe() error {
	// ULONG WMIAPI EnableTrace(
	// 	ULONG       Enable,
	// 	ULONG       EnableFlag,
	// 	ULONG       EnableLevel,
	// 	LPCGUID     ControlGuid,
	// 	TRACEHANDLE TraceHandle
	//   );
	//
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletrace
	ret := C.EnableTrace(
		C.ULONG(1),
		C.ULONG(s.keywordsMask), //Flags
		C.ULONG(s.level),
		(*C.GUID)(unsafe.Pointer(&s.guid)),
		s.hSession,
	)

	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return fmt.Errorf("enable trace failed; %v", status)
	}

	return nil
}

func (s *EtwSession) unsubscribe() error {
	// ULONG WMIAPI EnableTrace(
	// 	ULONG       Enable,
	// 	ULONG       EnableFlag,
	// 	ULONG       EnableLevel,
	// 	LPCGUID     ControlGuid,
	// 	TRACEHANDLE TraceHandle
	//   );
	ret := C.EnableTrace(
		C.ULONG(0),
		C.ULONG(s.keywordsMask), //Flags
		C.ULONG(s.level),
		(*C.GUID)(unsafe.Pointer(&s.guid)),
		s.hSession,
	)
	status := windows.Errno(ret)
	switch status {
	case windows.ERROR_SUCCESS, windows.ERROR_NOT_FOUND:
		return nil
	}

	return status
}
