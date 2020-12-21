// +build windows

package session

/*
#include "session.h"
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/tarusov/etw/internal/provider"

	"golang.org/x/sys/windows"
)

// EtwSession implements ETW consumer session.
type EtwSession struct {
	sessionName      []uint16      // Unique session sessionName (WCHAR).
	hSession         C.TRACEHANDLE // Session handler index.
	propertiesBuf    []byte        // Session properties buffer.
	guid             provider.GUID // ETW provider guid.
	level            traceLevel    // Event tracing level.
	keywordsMask     uint64        // kernel args mask.
	enableProperties []C.ULONG     // Enabled properties.

	callback func([]byte) // event callback func.
}

// New creates new session with specified params.
func New(providerName string, traceLevel string, kernelArgs []string) (*EtwSession, error) {
	level, err := parseTraceLevel(traceLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trace level; %v", err)
	}

	guid, err := provider.ParseName(providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse provider sessionName; %v", err)
	}

	var keywordsMask uint64
	if len(kernelArgs) > 0 {
		keywords, err := provider.EnumerateProviderKeywords(guid)
		if err != nil {
			return nil, fmt.Errorf("failed to get provider keywords; %v", err)
		}

		// Create uppercase duplicates because such an input from the config.
		for k, v := range keywords {
			keywords[strings.ToUpper(k)] = v
		}

		for _, arg := range kernelArgs {
			if mask, ok := keywords[arg]; ok {
				keywordsMask |= mask
			}
		}
	}

	sessionName, err := windows.UTF16FromString("go-etw-" + randomName())
	if err != nil {
		return nil, fmt.Errorf("failed to create session name: %v", err)
	}

	s := &EtwSession{
		sessionName:  sessionName,
		guid:         guid,
		level:        level,
		keywordsMask: keywordsMask,
	}

	if err := s.createSession(); err != nil {
		return nil, fmt.Errorf("failed to create session; %v", err)
	}

	return s, nil
}

// create wraps StartTraceW.
func (s *EtwSession) createSession() error {
	// We need to allocate a sequential buffer for a structure and a session sessionName
	// which will be placed there by an API call (for the future calls).
	//
	// (Ref: https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header#members)
	//
	// The only way to do it in go -- unsafe cast of the allocated memory.
	sessionNameSize := len(s.sessionName) * int(unsafe.Sizeof(s.sessionName[0]))
	bufSize := int(unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{})) + sessionNameSize
	propertiesBuf := make([]byte, bufSize)

	// We will use Query Performance Counter for timestamp cos it gives us higher
	// time resolution. Event timestamps however would be converted to the common
	// FileTime due to absence of PROCESS_TRACE_MODE_RAW_TIMESTAMP in LogFileMode.
	//
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
	pProperties := (C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&propertiesBuf[0]))
	pProperties.Wnode.BufferSize = C.ulong(bufSize)
	pProperties.Wnode.ClientContext = 1 // QPC for event Timestamp
	pProperties.Wnode.Flags = C.WNODE_FLAG_TRACED_GUID

	// Mark that we are going to process events in real time using a callback.
	pProperties.LogFileMode = C.EVENT_TRACE_REAL_TIME_MODE

	ret := C.StartTraceW(
		&s.hSession,
		C.LPWSTR(unsafe.Pointer(&s.sessionName[0])),
		pProperties,
	)
	switch err := windows.Errno(ret); err {
	case windows.ERROR_ALREADY_EXISTS:
		return ExistsError{SessionName: string(utf16.Decode(s.sessionName))}
	case windows.ERROR_SUCCESS:
		s.propertiesBuf = propertiesBuf
		return nil
	default:
		return fmt.Errorf("StartTraceW failed; %v", err)
	}
}

// Process starts processing of ETW events. Events will be passed to @cb
// synchronously and sequentially. Take a look to EventCallback documentation
// for more info about events processing.
//
// N.B. Process blocks until `.Close` being called!
func (s *EtwSession) Process(cb func([]byte)) error {
	s.callback = cb

	if err := s.subscribe(); err != nil {
		return fmt.Errorf("failed to subscribe: %v", err)
	}

	cgoKey := newCallbackKey(s)
	defer freeCallbackKey(cgoKey)

	// Will block here until being closed.
	if err := s.processEvents(cgoKey); err != nil {
		return fmt.Errorf("error processing events: %v", err)
	}

	return nil
}

// processEvents subscribes to the actual provider events and starts its processing.
func (s *EtwSession) processEvents(callbackContextKey uintptr) error {
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew
	traceHandle := C.OpenTraceHelper(
		(C.LPWSTR)(unsafe.Pointer(&s.sessionName[0])),
		(C.PVOID)(callbackContextKey),
	)
	if C.INVALID_PROCESSTRACE_HANDLE == traceHandle {
		return fmt.Errorf("OpenTraceW failed; %v", windows.GetLastError())
	}

	// BLOCKS UNTIL CLOSED!
	//
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
	// ETW_APP_DECLSPEC_DEPRECATED ULONG WMIAPI ProcessTrace(
	// 	PTRACEHANDLE HandleArray,
	// 	ULONG        HandleCount,
	// 	LPFILETIME   StartTime,
	// 	LPFILETIME   EndTime
	// );
	ret := C.ProcessTrace(
		C.PTRACEHANDLE(&traceHandle),
		1,   // ^ Imagine we pass an array with 1 element here.
		nil, // Do not want to limit StartTime (default is from now).
		nil, // Do not want to limit EndTime.
	)
	switch status := windows.Errno(ret); status {
	case windows.ERROR_SUCCESS, windows.ERROR_CANCELLED:
		return nil // Cancelled is obviously ok when we block until closing.
	default:
		return fmt.Errorf("ProcessTrace failed; %v", status)
	}
}

// Close EtwSession.
func (s *EtwSession) Close() error {
	if err := s.unsubscribe(); err != nil {
		return fmt.Errorf("failed to disable subscribtion; %v", err)
	}
	if err := s.stopSession(); err != nil {
		return fmt.Errorf("failed to stop session; %v", err)
	}

	return nil
}

// stopSession wraps ControlTraceW with EVENT_TRACE_CONTROL_STOP.
func (s *EtwSession) stopSession() error {
	// ULONG WMIAPI ControlTraceW(
	//  TRACEHANDLE             TraceHandle,
	//  LPCWSTR                 InstanceName,
	//  PEVENT_TRACE_PROPERTIES Properties,
	//  ULONG                   ControlCode
	// );
	ret := C.ControlTraceW(
		s.hSession,
		nil,
		(C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&s.propertiesBuf[0])),
		C.EVENT_TRACE_CONTROL_STOP)

	// If you receive ERROR_MORE_DATA when stopping the session, ETW will have
	// already stopped the session before generating this error.
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
	switch status := windows.Errno(ret); status {
	case windows.ERROR_MORE_DATA, windows.ERROR_SUCCESS:
		return nil
	default:
		return status
	}
}

// randomName create random sessionName for session.
func randomName() string {
	rand.Seed(time.Now().UnixNano())
	const alph = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = alph[rand.Intn(len(alph))]
	}

	return string(b)
}

// We can't pass Go-land pointers to the C-world so we use a classical trick
// storing real pointers inside global map and passing to C "fake pointers"
// which are actually map keys.
//
//nolint:gochecknoglobals
var (
	sessions       sync.Map
	sessionCounter uintptr
)

// newCallbackKey stores a @ptr inside a global storage returning its' key.
// After use the key should be freed using `freeCallbackKey`.
func newCallbackKey(ptr *EtwSession) uintptr {
	key := atomic.AddUintptr(&sessionCounter, 1)
	sessions.Store(key, ptr)

	return key
}

func freeCallbackKey(key uintptr) {
	sessions.Delete(key)
}

// handleEvent is exported to guarantee C calling convention (cdecl).
//
// The function should be defined here but would be linked and used inside
// C code in `session.c`.
//
//export handleEvent
func handleEvent(eventRecord C.PEVENT_RECORD) {
	key := uintptr(eventRecord.UserContext)
	targetSession, ok := sessions.Load(key)
	if !ok {
		return
	}

	event := NewEvent(eventRecord)
	defer event.Free()

	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	targetSession.(*EtwSession).callback(data)
}
