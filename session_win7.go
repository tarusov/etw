// +build windows,!winxp

package etw

/*
	#cgo LDFLAGS: -ltdh

	#include "session_win7.h"
*/
import "C"
import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Session represents a Windows event tracing session that is ready to start
// events processing. Session subscribes to the given ETW provider only on
// `.Process`  call, so having a Session without `.Process` called should not
// affect OS performance.
//
// Session should be closed via `.Close` call to free obtained OS resources
// even if `.Process` has never been called.
type Session struct {
	guid     windows.GUID
	config   SessionOptions
	callback EventCallback

	etwSessionName []uint16
	hSession       C.TRACEHANDLE
	propertiesBuf  []byte
}

// EventCallback is any function that could handle an ETW event. EventCallback
// is called synchronously and sequentially on every event received by Session
// one by one.
//
// If EventCallback can't handle all ETW events produced, OS will handle a
// tricky file-based cache for you, however, it's recommended not to perform
// long-running tasks inside a callback.
//
// N.B. Event pointer @e is valid ONLY inside a callback. You CAN'T copy a
// whole event, only EventHeader, EventProperties and ExtendedEventInfo
// separately.
type EventCallback func(e *Event)

// NewSession creates a Windows event tracing session instance. Session with no
// options provided is a usable session, but it could be a bit noisy. It's
// recommended to refine the session with level and match keywords options
// to get rid of unnecessary events.
//
// You MUST call `.Close` on session after use to clear associated resources,
// otherwise it will leak in OS internals until system reboot.
func NewSession(providerGUID windows.GUID, options ...Option) (*Session, error) {
	defaultConfig := SessionOptions{
		Name:  "go-etw-" + randomName(),
		Level: TRACE_LEVEL_VERBOSE,
	}
	for _, opt := range options {
		opt(&defaultConfig)
	}
	s := Session{
		guid:   providerGUID,
		config: defaultConfig,
	}

	utf16Name, err := windows.UTF16FromString(s.config.Name)
	if err != nil {
		return nil, fmt.Errorf("incorrect session name; %v", err) // unlikely
	}
	s.etwSessionName = utf16Name

	if err := s.createETWSession(); err != nil {
		return nil, fmt.Errorf("failed to create session; %v", err)
	}
	// TODO: consider setting a finalizer with .Close

	return &s, nil
}

// Process starts processing of ETW events. Events will be passed to @cb
// synchronously and sequentially. Take a look to EventCallback documentation
// for more info about events processing.
//
// N.B. Process blocks until `.Close` being called!
func (s *Session) Process(cb EventCallback) error {
	s.callback = cb

	if err := s.subscribeToProvider(); err != nil {
		return fmt.Errorf("failed to subscribe to provider; %v", err)
	}

	cgoKey := newCallbackKey(s)
	defer freeCallbackKey(cgoKey)

	// Will block here until being closed.
	if err := s.processEvents(cgoKey); err != nil {
		return fmt.Errorf("error processing events; %v", err)
	}
	return nil
}

// UpdateOptions changes subscription parameters in runtime. The only option
// that can't be updated is session name. To change session name -- stop and
// recreate a session with new desired name.
func (s *Session) UpdateOptions(options ...Option) error {
	for _, opt := range options {
		opt(&s.config)
	}
	if err := s.subscribeToProvider(); err != nil {
		return err
	}
	return nil
}

// Close stops trace session and frees associated resources.
func (s *Session) Close() error {
	// "Be sure to disable all providers before stopping the session."
	// https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session
	if err := s.unsubscribeFromProvider(); err != nil {
		return fmt.Errorf("failed to disable provider; %v", err)
	}

	if err := s.stopSession(); err != nil {
		return fmt.Errorf("failed to stop session; %v", err)
	}
	return nil
}

// KillSession forces the session with a given @name to stop. Don't having a
// session handle we can't shutdown it gracefully unsubscribing from all the
// providers first, so we just stop the session itself.
//
// Use KillSession only to destroy session you've lost control over. If you
// have a session handle always prefer `.Close`.
func KillSession(name string) error {
	nameUTF16, err := windows.UTF16FromString(name)
	if err != nil {
		return fmt.Errorf("failed to convert session name to utf16; %v", err)
	}
	sessionNameLength := len(nameUTF16) * int(unsafe.Sizeof(nameUTF16[0]))

	//
	// For a graceful shutdown we should unsubscribe from all providers associated
	// with the session, but we can't find a way to query them using WinAPI.
	// So we just ask the session to stop and hope that wont hurt anything too bad.
	//

	// We don't know if this session was opened with the log file or not
	// (session could be opened without our library) so allocate memory for LogFile name too.
	const maxLengthLogfileName = 1024
	bufSize := int(unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{})) + sessionNameLength + maxLengthLogfileName
	propertiesBuf := make([]byte, bufSize)
	pProperties := (C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&propertiesBuf[0]))
	pProperties.Wnode.BufferSize = C.ulong(bufSize)

	// ULONG WMIAPI ControlTraceW(
	//  TRACEHANDLE             TraceHandle,
	//  LPCWSTR                 InstanceName,
	//  PEVENT_TRACE_PROPERTIES Properties,
	//  ULONG                   ControlCode
	// );
	ret := C.ControlTraceW(
		0,
		(*C.ushort)(unsafe.Pointer(&nameUTF16[0])),
		pProperties,
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

// createETWSession wraps StartTraceW.
func (s *Session) createETWSession() error {
	// We need to allocate a sequential buffer for a structure and a session name
	// which will be placed there by an API call (for the future calls).
	//
	// (Ref: https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header#members)
	//
	// The only way to do it in go -- unsafe cast of the allocated memory.
	sessionNameSize := len(s.etwSessionName) * int(unsafe.Sizeof(s.etwSessionName[0]))
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
		C.LPWSTR(unsafe.Pointer(&s.etwSessionName[0])),
		pProperties,
	)
	switch err := windows.Errno(ret); err {
	case windows.ERROR_ALREADY_EXISTS:
		return ExistsError{SessionName: s.config.Name}
	case windows.ERROR_SUCCESS:
		s.propertiesBuf = propertiesBuf
		return nil
	default:
		return fmt.Errorf("StartTraceW failed; %v", err)
	}
}

// processEvents subscribes to the actual provider events and starts its processing.
func (s *Session) processEvents(callbackContextKey uintptr) error {
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew
	traceHandle := C.OpenTraceHelper(
		(C.LPWSTR)(unsafe.Pointer(&s.etwSessionName[0])),
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

// stopSession wraps ControlTraceW with EVENT_TRACE_CONTROL_STOP.
func (s *Session) stopSession() error {
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

func randomName() string {
	if g, err := windows.GenerateGUID(); err == nil {
		return g.String()
	}

	// should be almost impossible, right?
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
func newCallbackKey(ptr *Session) uintptr {
	key := atomic.AddUintptr(&sessionCounter, 1)
	sessions.Store(key, ptr)

	return key
}

func freeCallbackKey(key uintptr) {
	sessions.Delete(key)
}

func eventHeaderToGo(header C.EVENT_HEADER) EventHeader {
	return EventHeader{
		EventDescriptor: eventDescriptorToGo(header.EventDescriptor),
		ThreadID:        uint32(header.ThreadId),
		ProcessID:       uint32(header.ProcessId),
		TimeStamp:       stampToTime(C.GetTimeStamp(header)),
		ProviderID:      windowsGUIDToGo(header.ProviderId),
		ActivityID:      windowsGUIDToGo(header.ActivityId),

		Flags:         uint16(header.Flags),
		KernelTime:    uint32(C.GetKernelTime(header)),
		UserTime:      uint32(C.GetUserTime(header)),
		ProcessorTime: uint64(C.GetProcessorTime(header)),
	}
}

func eventDescriptorToGo(descriptor C.EVENT_DESCRIPTOR) EventDescriptor {
	return EventDescriptor{
		ID:      uint16(descriptor.Id),
		Version: uint8(descriptor.Version),
		Channel: uint8(descriptor.Channel),
		Level:   uint8(descriptor.Level),
		OpCode:  uint8(descriptor.Opcode),
		Task:    uint16(descriptor.Task),
		Keyword: uint64(descriptor.Keyword),
	}
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

	evt := &Event{
		Header:      eventHeaderToGo(eventRecord.EventHeader),
		eventRecord: eventRecord,
	}
	targetSession.(*Session).callback(evt)
	evt.eventRecord = nil
}

// subscribeToProvider wraps EnableTraceEx2 with EVENT_CONTROL_CODE_ENABLE_PROVIDER.
func (s *Session) subscribeToProvider() error {
	// https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session
	params := C.ENABLE_TRACE_PARAMETERS{
		Version: 2, // ENABLE_TRACE_PARAMETERS_VERSION_2
	}
	for _, p := range s.config.EnableProperties {
		params.EnableProperty |= C.ULONG(p)
	}

	// ULONG WMIAPI EnableTraceEx2(
	//	TRACEHANDLE              TraceHandle,
	//	LPCGUID                  ProviderId,
	//	ULONG                    ControlCode,
	//	UCHAR                    Level,
	//	ULONGLONG                MatchAnyKeyword,
	//	ULONGLONG                MatchAllKeyword,
	//	ULONG                    Timeout,
	//	PENABLE_TRACE_PARAMETERS EnableParameters
	// );
	//
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
	ret := C.EnableTraceEx2(
		s.hSession,
		(*C.GUID)(unsafe.Pointer(&s.guid)),
		C.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		C.UCHAR(s.config.Level),
		C.ULONGLONG(s.config.MatchAnyKeyword),
		C.ULONGLONG(s.config.MatchAllKeyword),
		0,       // Timeout set to zero to enable the trace asynchronously
		&params, //nolint:gocritic // TODO: dupSubExpr?? gocritic bug?
	)

	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return fmt.Errorf("EVENT_CONTROL_CODE_ENABLE_PROVIDER failed; %v", status)
	}
	return nil
}

// unsubscribeFromProvider wraps EnableTraceEx2 with EVENT_CONTROL_CODE_DISABLE_PROVIDER.
func (s *Session) unsubscribeFromProvider() error {
	// ULONG WMIAPI EnableTraceEx2(
	//	TRACEHANDLE              TraceHandle,
	//	LPCGUID                  ProviderId,
	//	ULONG                    ControlCode,
	//	UCHAR                    Level,
	//	ULONGLONG                MatchAnyKeyword,
	//	ULONGLONG                MatchAllKeyword,
	//	ULONG                    Timeout,
	//	PENABLE_TRACE_PARAMETERS EnableParameters
	// );
	ret := C.EnableTraceEx2(
		s.hSession,
		(*C.GUID)(unsafe.Pointer(&s.guid)),
		C.EVENT_CONTROL_CODE_DISABLE_PROVIDER,
		0,
		0,
		0,
		0,
		nil)
	status := windows.Errno(ret)
	switch status {
	case windows.ERROR_SUCCESS, windows.ERROR_NOT_FOUND:
		return nil
	}
	return status
}

// EVENT

// Event is a single event record received from ETW provider. The only thing
// that is parsed implicitly is an EventHeader (which just translated from C
// structures mostly 1:1), all other data are parsed on-demand.
//
// Events will be passed to the user EventCallback. It's invalid to use Event
// methods outside of an EventCallback.
type Event struct {
	Header      EventHeader
	eventRecord C.PEVENT_RECORD
}

// EventHeader contains an information that is common for every ETW event
// record.
//
// EventHeader fields is self-descriptive. If you need more info refer to the
// original struct docs:
// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
type EventHeader struct {
	EventDescriptor

	ThreadID  uint32
	ProcessID uint32
	TimeStamp time.Time

	ProviderID windows.GUID
	ActivityID windows.GUID

	Flags         uint16
	KernelTime    uint32
	UserTime      uint32
	ProcessorTime uint64
}

// HasCPUTime returns true if the event has separate UserTime and KernelTime
// measurements. Otherwise the value of UserTime and KernelTime is meaningless
// and you should use ProcessorTime instead.
func (h EventHeader) HasCPUTime() bool {
	switch {
	case h.Flags&C.EVENT_HEADER_FLAG_NO_CPUTIME != 0:
		return false
	case h.Flags&C.EVENT_HEADER_FLAG_PRIVATE_SESSION != 0:
		return false
	default:
		return true
	}
}

// EventDescriptor contains low-level metadata that defines received event.
// Most of fields could be used to refine events filtration.
//
// For detailed information about fields values refer to EVENT_DESCRIPTOR docs:
// https://docs.microsoft.com/ru-ru/windows/win32/api/evntprov/ns-evntprov-event_descriptor
type EventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	OpCode  uint8
	Task    uint16
	Keyword uint64
}

// EventProperties returns a map that represents events-specific data provided
// by event producer. Returned data depends on the provider, event type and even
// provider and event versions.
//
// The simplest (and the recommended) way to parse event data is to use TDH
// family of functions that render event data to the strings exactly as you can
// see it in the Event Viewer.
//
// EventProperties returns a map that could be interpreted as "structure that
// fit inside a map". Map keys is a event data field names, map values is field
// values rendered to strings. So map values could be one of the following:
//		- `[]string` for arrays of any types;
//		- `map[string]interface{}` for fields that are structures;
//		- `string` for any other values.
//
// Take a look at `TestParsing` for possible EventProperties values.
func (e *Event) EventProperties() (map[string]interface{}, error) {
	if e.eventRecord == nil {
		return nil, fmt.Errorf("usage of Event is invalid outside of EventCallback")
	}

	if e.eventRecord.EventHeader.Flags == C.EVENT_HEADER_FLAG_STRING_ONLY {
		return map[string]interface{}{
			"_": C.GoString((*C.char)(e.eventRecord.UserData)),
		}, nil
	}

	p, err := newPropertyParser(e.eventRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to parse event properties; %v", err)
	}
	defer p.free()

	properties := make(map[string]interface{}, int(p.info.TopLevelPropertyCount))
	for i := 0; i < int(p.info.TopLevelPropertyCount); i++ {
		name := p.getPropertyName(i)
		value, err := p.getPropertyValue(i)
		if err != nil {
			// Parsing values we consume given event data buffer with var length chunks.
			// If we skip any -- we'll lost offset, so fail early.
			return nil, fmt.Errorf("failed to parse %q value; %v", name, err)
		}
		properties[name] = value
	}
	return properties, nil
}

// ExtendedEventInfo contains additional information about received event. All
// ExtendedEventInfo fields are optional and are nils being not set by provider.
//
// Presence of concrete fields is controlled by WithProperty option and an
// ability of event provider to set the required fields.
//
// More info about fields is available at EVENT_HEADER_EXTENDED_DATA_ITEM.ExtType
// documentation:
// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header_extended_data_item
type ExtendedEventInfo struct {
	SessionID    *uint32
	ActivityID   *windows.GUID
	UserSID      *windows.SID
	InstanceInfo *EventInstanceInfo
	StackTrace   *EventStackTrace
}

// EventInstanceInfo defines the relationship between events if its provided.
type EventInstanceInfo struct {
	InstanceID       uint32
	ParentInstanceID uint32
	ParentGUID       windows.GUID
}

// EventStackTrace describes a call trace of the event occurred.
type EventStackTrace struct {
	MatchedID uint64
	Addresses []uint64
}

// ExtendedInfo extracts ExtendedEventInfo structure from native buffers of
// received event record.
//
// If no ExtendedEventInfo is available inside an event record function returns
// the structure with all fields set to nil.
func (e *Event) ExtendedInfo() ExtendedEventInfo {
	if e.eventRecord == nil { // Usage outside of event callback.
		return ExtendedEventInfo{}
	}
	if e.eventRecord.EventHeader.Flags&C.EVENT_HEADER_FLAG_EXTENDED_INFO == 0 {
		return ExtendedEventInfo{}
	}
	return e.parseExtendedInfo()
}

func (e *Event) parseExtendedInfo() ExtendedEventInfo {
	var extendedData ExtendedEventInfo
	for i := 0; i < int(e.eventRecord.ExtendedDataCount); i++ {
		dataPtr := unsafe.Pointer(uintptr(C.GetDataPtr(e.eventRecord.ExtendedData, C.int(i))))

		switch C.GetExtType(e.eventRecord.ExtendedData, C.int(i)) {
		case C.EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID:
			cGUID := (C.LPGUID)(dataPtr)
			goGUID := windowsGUIDToGo(*cGUID)
			extendedData.ActivityID = &goGUID

		case C.EVENT_HEADER_EXT_TYPE_SID:
			cSID := (*C.SID)(dataPtr)
			goSID, err := (*windows.SID)(unsafe.Pointer(cSID)).Copy()
			if err == nil {
				extendedData.UserSID = goSID
			}

		case C.EVENT_HEADER_EXT_TYPE_TS_ID:
			cSessionID := (C.PULONG)(dataPtr)
			goSessionID := uint32(*cSessionID)
			extendedData.SessionID = &goSessionID

		case C.EVENT_HEADER_EXT_TYPE_INSTANCE_INFO:
			instanceInfo := (C.PEVENT_EXTENDED_ITEM_INSTANCE)(dataPtr)
			extendedData.InstanceInfo = &EventInstanceInfo{
				InstanceID:       uint32(instanceInfo.InstanceId),
				ParentInstanceID: uint32(instanceInfo.ParentInstanceId),
				ParentGUID:       windowsGUIDToGo(instanceInfo.ParentGuid),
			}

		case C.EVENT_HEADER_EXT_TYPE_STACK_TRACE32:
			stack32 := (C.PEVENT_EXTENDED_ITEM_STACK_TRACE32)(dataPtr)

			// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace32#remarks
			dataSize := C.GetDataSize(e.eventRecord.ExtendedData, C.int(i))
			matchedIDSize := unsafe.Sizeof(C.ULONG64(0))
			arraySize := (uintptr(dataSize) - matchedIDSize) / unsafe.Sizeof(C.ULONG(0))

			address := make([]uint64, arraySize)
			for j := 0; j < int(arraySize); j++ {
				address[j] = uint64(C.GetAddress32(stack32, C.int(j)))
			}

			extendedData.StackTrace = &EventStackTrace{
				MatchedID: uint64(stack32.MatchId),
				Addresses: address,
			}

		case C.EVENT_HEADER_EXT_TYPE_STACK_TRACE64:
			stack64 := (C.PEVENT_EXTENDED_ITEM_STACK_TRACE64)(dataPtr)

			// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace64#remarks
			dataSize := C.GetDataSize(e.eventRecord.ExtendedData, C.int(i))
			matchedIDSize := unsafe.Sizeof(C.ULONG64(0))
			arraySize := (uintptr(dataSize) - matchedIDSize) / unsafe.Sizeof(C.ULONG64(0))

			address := make([]uint64, arraySize)
			for j := 0; j < int(arraySize); j++ {
				address[j] = uint64(C.GetAddress64(stack64, C.int(j)))
			}

			extendedData.StackTrace = &EventStackTrace{
				MatchedID: uint64(stack64.MatchId),
				Addresses: address,
			}

			// TODO:
			// EVENT_HEADER_EXT_TYPE_PEBS_INDEX, EVENT_HEADER_EXT_TYPE_PMC_COUNTERS
			// EVENT_HEADER_EXT_TYPE_PSM_KEY, EVENT_HEADER_EXT_TYPE_EVENT_KEY,
			// EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL
			// EVENT_HEADER_EXT_TYPE_PROV_TRAITS
		}
	}
	return extendedData
}

// propertyParser is used for parsing properties from raw EVENT_RECORD structure.
type propertyParser struct {
	record  C.PEVENT_RECORD
	info    C.PTRACE_EVENT_INFO
	data    uintptr
	endData uintptr
	ptrSize uintptr
}

func newPropertyParser(r C.PEVENT_RECORD) (*propertyParser, error) {
	info, err := getEventInformation(r)
	if err != nil {
		if info != nil {
			C.free(unsafe.Pointer(info))
		}
		return nil, fmt.Errorf("failed to get event information; %v", err)
	}
	ptrSize := unsafe.Sizeof(uint64(0))
	if r.EventHeader.Flags&C.EVENT_HEADER_FLAG_32_BIT_HEADER == C.EVENT_HEADER_FLAG_32_BIT_HEADER {
		ptrSize = unsafe.Sizeof(uint32(0))
	}
	return &propertyParser{
		record:  r,
		info:    info,
		ptrSize: ptrSize,
		data:    uintptr(r.UserData),
		endData: uintptr(r.UserData) + uintptr(r.UserDataLength),
	}, nil
}

// getEventInformation wraps TdhGetEventInformation. It extracts some kind of
// simplified event information used by Tdh* family of function.
//
// Returned info MUST be freed after use.
func getEventInformation(pEvent C.PEVENT_RECORD) (C.PTRACE_EVENT_INFO, error) {
	var (
		pInfo      C.PTRACE_EVENT_INFO
		bufferSize C.ulong
	)

	// Retrieve a buffer size.
	ret := C.TdhGetEventInformation(pEvent, 0, nil, pInfo, &bufferSize)
	if windows.Errno(ret) == windows.ERROR_INSUFFICIENT_BUFFER {
		pInfo = C.PTRACE_EVENT_INFO(C.malloc(C.size_t(bufferSize)))
		if pInfo == nil {
			return nil, fmt.Errorf("malloc(%v) failed", bufferSize)
		}

		// Fetch the buffer itself.
		ret = C.TdhGetEventInformation(pEvent, 0, nil, pInfo, &bufferSize)
	}

	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return pInfo, fmt.Errorf("TdhGetEventInformation failed; %v", status)
	}

	return pInfo, nil
}

// free frees associated PTRACE_EVENT_INFO if any assigned.
func (p *propertyParser) free() {
	if p.info != nil {
		C.free(unsafe.Pointer(p.info))
	}
}

// getPropertyName returns a name of the @i-th event property.
func (p *propertyParser) getPropertyName(i int) string {
	propertyName := uintptr(C.GetPropertyName(p.info, C.int(i)))
	length := C.wcslen((C.PWCHAR)(unsafe.Pointer(propertyName)))
	return createUTF16String(propertyName, int(length))
}

// getPropertyValue retrieves a value of @i-th property.
//
// N.B. getPropertyValue HIGHLY depends not only on @i but also on memory
// offsets, so check twice calling with non-sequential indexes.
func (p *propertyParser) getPropertyValue(i int) (interface{}, error) {
	var arraySizeC C.uint
	ret := C.GetArraySize(p.record, p.info, C.int(i), &arraySizeC)
	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return nil, fmt.Errorf("failed to get array size; %v", status)
	}

	arraySize := int(arraySizeC)
	result := make([]interface{}, arraySize)
	for j := 0; j < arraySize; j++ {
		var (
			value interface{}
			err   error
		)
		// Note that we pass same idx to parse function. Actual returned values are controlled
		// by data pointers offsets.
		if int(C.PropertyIsStruct(p.info, C.int(i))) == 1 {
			value, err = p.parseStruct(i)
		} else {
			value, err = p.parseSimpleType(i)
		}
		if err != nil {
			return nil, err
		}
		result[j] = value
	}

	if int(C.PropertyIsArray(p.info, C.int(i))) == 1 {
		return result, nil
	}
	return result[0], nil
}

// parseStruct tries to extract fields of embedded structure at property @i.
func (p *propertyParser) parseStruct(i int) (map[string]interface{}, error) {
	startIndex := int(C.GetStructStartIndex(p.info, C.int(i)))
	lastIndex := int(C.GetStructLastIndex(p.info, C.int(i)))

	structure := make(map[string]interface{}, lastIndex-startIndex)
	for j := startIndex; j < lastIndex; j++ {
		name := p.getPropertyName(j)
		value, err := p.getPropertyValue(j)
		if err != nil {
			return nil, fmt.Errorf("failed parse field %q of complex property type; %v", name, err)
		}
		structure[name] = value
	}
	return structure, nil
}

// For some weird reasons non of mingw versions has TdhFormatProperty defined
// so the only possible way is to use a DLL here.
//
//nolint:gochecknoglobals
var (
	tdh               = windows.NewLazySystemDLL("Tdh.dll")
	tdhFormatProperty = tdh.NewProc("TdhFormatProperty")
)

// parseSimpleType wraps TdhFormatProperty to get rendered to string value of
// @i-th event property.
func (p *propertyParser) parseSimpleType(i int) (string, error) {
	mapInfo, err := getMapInfo(p.record, p.info, i)
	if err != nil {
		return "", fmt.Errorf("failed to get map info; %v", err)
	}

	var propertyLength C.uint
	ret := C.GetPropertyLength(p.record, p.info, C.int(i), &propertyLength)
	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return "", fmt.Errorf("failed to get property length; %v", status)
	}

	inType := uintptr(C.GetInType(p.info, C.int(i)))
	outType := uintptr(C.GetOutType(p.info, C.int(i)))

	// We are going to guess a value size to save a DLL call, so preallocate.
	var (
		userDataConsumed  C.int
		formattedDataSize C.int = 50
	)
	formattedData := make([]byte, int(formattedDataSize))

retryLoop:
	for {
		r0, _, _ := tdhFormatProperty.Call(
			uintptr(unsafe.Pointer(p.record)),
			uintptr(mapInfo),
			p.ptrSize,
			inType,
			outType,
			uintptr(propertyLength),
			p.endData-p.data,
			p.data,
			uintptr(unsafe.Pointer(&formattedDataSize)),
			uintptr(unsafe.Pointer(&formattedData[0])),
			uintptr(unsafe.Pointer(&userDataConsumed)),
		)

		switch status := windows.Errno(r0); status {
		case windows.ERROR_INSUFFICIENT_BUFFER:
			formattedData = make([]byte, int(formattedDataSize))
			continue
		case windows.ERROR_SUCCESS:
			break retryLoop
		default:
			return "", fmt.Errorf("TdhFormatProperty failed; %v", status)
		}
	}
	p.data += uintptr(userDataConsumed)

	return createUTF16String(uintptr(unsafe.Pointer(&formattedData[0])), int(formattedDataSize)), nil
}

// getMapInfo retrieve the mapping between the @i-th field and the structure it represents.
// If that mapping exists, function extracts it and returns a pointer to the buffer with
// extracted info, if not function can legitimately return `nil, nil`.
func getMapInfo(event C.PEVENT_RECORD, info C.PTRACE_EVENT_INFO, i int) (unsafe.Pointer, error) {
	mapName := C.GetMapName(info, C.int(i))

	// Query map info if any exists.
	var mapSize C.ulong
	ret := C.TdhGetEventMapInformation(event, mapName, nil, &mapSize)
	switch status := windows.Errno(ret); status {
	case windows.ERROR_NOT_FOUND:
		return nil, nil // Pretty ok, just no map info
	case windows.ERROR_INSUFFICIENT_BUFFER:
		// Info exists -- need a buffer.
	default:
		return nil, fmt.Errorf("TdhGetEventMapInformation failed to get size; %v", status)
	}

	// Get the info itself.
	mapInfo := make([]byte, int(mapSize))
	ret = C.TdhGetEventMapInformation(
		event,
		mapName,
		(C.PEVENT_MAP_INFO)(unsafe.Pointer(&mapInfo[0])),
		&mapSize)
	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return nil, fmt.Errorf("TdhGetEventMapInformation failed; %v", status)
	}

	if len(mapInfo) == 0 {
		return nil, nil
	}
	return unsafe.Pointer(&mapInfo[0]), nil
}

func windowsGUIDToGo(guid C.GUID) windows.GUID {
	var data4 [8]byte
	for i := range data4 {
		data4[i] = byte(guid.Data4[i])
	}
	return windows.GUID{
		Data1: uint32(guid.Data1),
		Data2: uint16(guid.Data2),
		Data3: uint16(guid.Data3),
		Data4: data4,
	}
}

// stampToTime translates FileTime to a golang time. Same as in standard packages.
func stampToTime(quadPart C.LONGLONG) time.Time {
	ft := windows.Filetime{
		HighDateTime: uint32(quadPart >> 32),
		LowDateTime:  uint32(quadPart & math.MaxUint32),
	}
	return time.Unix(0, ft.Nanoseconds())
}

// Creates UTF16 string from raw parts.
//
// Actually in go we have no way to make a slice from raw parts, ref:
// - https://github.com/golang/go/issues/13656
// - https://github.com/golang/go/issues/19367
// So the recommended way is "a fake cast" to the array with maximal len
// with a following slicing.
// Ref: https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices
func createUTF16String(ptr uintptr, len int) string {
	if len == 0 {
		return ""
	}
	bytes := (*[1 << 29]uint16)(unsafe.Pointer(ptr))[:len:len]
	return windows.UTF16ToString(bytes)
}
