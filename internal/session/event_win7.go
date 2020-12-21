// +build windows
// +build !winxp

package session

/*
#cgo LDFLAGS: -ltdh
#include "session_win7.h"
*/
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/tarusov/etw/internal/provider"
	"github.com/tarusov/etw/internal/winapi"

	"golang.org/x/sys/windows"
)

// parseEventHeader returns event header parameters.
func parseEventHeader(header C.EVENT_HEADER) EventHeader {
	return EventHeader{
		Descriptor: parseEventDescriptor(header.EventDescriptor),
		ThreadID:   uint32(header.ThreadId),
		ProcessID:  uint32(header.ProcessId),
		TimeStamp:  stampToTime(C.GetTimeStamp(header)),
		ProviderID: guidToGo(header.ProviderId),
		ActivityID: guidToGo(header.ActivityId),

		Flags:         uint16(header.Flags),
		KernelTime:    uint32(C.GetKernelTime(header)),
		UserTime:      uint32(C.GetUserTime(header)),
		ProcessorTime: uint64(C.GetProcessorTime(header)),
	}
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
	SessionID    *uint32            `json:"session_id"`
	ActivityID   *provider.GUID     `json:"activity_id"`
	UserSID      *windows.SID       `json:"user_sid"`
	InstanceInfo *EventInstanceInfo `json:"instance_info"`
	StackTrace   *EventStackTrace   `json:"stacktrace"`
}

// EventInstanceInfo defines the relationship between events if its provided.
type EventInstanceInfo struct {
	InstanceID       uint32        `json:"id"`
	ParentInstanceID uint32        `json:"parent_id"`
	ParentGUID       provider.GUID `json:"parent_guid"`
}

// EventStackTrace describes a call trace of the event occurred.
type EventStackTrace struct {
	MatchedID uint64   `json:"matched_id"`
	Addresses []uint64 `json:"addresses"`
}

// parseExtendedInfo returns extended info for event.
func parseExtendedInfo(record C.PEVENT_RECORD) interface{} {
	if int(record.ExtendedDataCount) == 0 {
		return nil
	}

	var extendedData ExtendedEventInfo
	for i := 0; i < int(record.ExtendedDataCount); i++ {
		var dataPtr winapi.ULONGLONG
		dataPtr.Pointer = unsafe.Pointer(uintptr(C.GetDataPtr(record.ExtendedData, C.int(i))))

		switch C.GetExtType(record.ExtendedData, C.int(i)) {
		case C.EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID:
			cGUID := (C.LPGUID)(dataPtr.Pointer)
			goGUID := guidToGo(*cGUID)
			extendedData.ActivityID = &goGUID

		case C.EVENT_HEADER_EXT_TYPE_SID:
			cSID := (*C.SID)(dataPtr.Pointer)
			goSID, err := (*windows.SID)(unsafe.Pointer(cSID)).Copy()
			if err == nil {
				extendedData.UserSID = goSID
			}

		case C.EVENT_HEADER_EXT_TYPE_TS_ID:
			cSessionID := (C.PULONG)(dataPtr.Pointer)
			goSessionID := uint32(*cSessionID)
			extendedData.SessionID = &goSessionID

		case C.EVENT_HEADER_EXT_TYPE_INSTANCE_INFO:
			instanceInfo := (C.PEVENT_EXTENDED_ITEM_INSTANCE)(dataPtr.Pointer)
			extendedData.InstanceInfo = &EventInstanceInfo{
				InstanceID:       uint32(instanceInfo.InstanceId),
				ParentInstanceID: uint32(instanceInfo.ParentInstanceId),
				ParentGUID:       guidToGo(instanceInfo.ParentGuid),
			}

		case C.EVENT_HEADER_EXT_TYPE_STACK_TRACE32:
			stack32 := (C.PEVENT_EXTENDED_ITEM_STACK_TRACE32)(dataPtr.Pointer)

			// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace32#remarks
			dataSize := C.GetDataSize(record.ExtendedData, C.int(i))
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
			stack64 := (C.PEVENT_EXTENDED_ITEM_STACK_TRACE64)(dataPtr.Pointer)

			// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace64#remarks
			dataSize := C.GetDataSize(record.ExtendedData, C.int(i))
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

	return &extendedData
}

func parseEventInfo(r C.PEVENT_RECORD) interface{} {
	parser, err := newPropertyParser(r)
	if err != nil {
		return nil
	}
	defer parser.free()

	properties := make(map[string]interface{}, int(parser.info.TopLevelPropertyCount))
	for i := 0; i < int(parser.info.TopLevelPropertyCount); i++ {
		name := parser.getPropertyName(i)
		value, err := parser.getPropertyValue(i)
		if err != nil {
			return nil
		}
		properties[name] = value
	}

	return properties
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
	info, err := getRecordInfo(r)
	if err != nil {
		if info != nil {
			C.free(unsafe.Pointer(info))
		}
		return nil, fmt.Errorf("failed to get event information: %v", err)
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
func getRecordInfo(pEvent C.PEVENT_RECORD) (C.PTRACE_EVENT_INFO, error) {
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
		if status != windows.ERROR_NOT_FOUND {
			return nil, fmt.Errorf("TdhGetEventInformation failed: %v", status)
		}
		return nil, fmt.Errorf("no schema for event")
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
		return "", fmt.Errorf("failed to get map info: %v", err)
	}

	var propertyLength C.uint
	ret := C.GetPropertyLength(p.record, p.info, C.int(i), &propertyLength)
	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return "", fmt.Errorf("failed to get property length: %v", status)
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
			return "", fmt.Errorf("TdhFormatProperty failed: %v", status)
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
