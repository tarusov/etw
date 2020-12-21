// +build windows

package session

/*
#include <windows.h>
#include <evntcons.h>
*/
import "C"
import (
	"math"
	"time"

	"github.com/tarusov/etw/internal/provider"

	"golang.org/x/sys/windows"
)

// Event is a single event record received from ETW provider. The only thing
// that is parsed implicitly is an EventHeader (which just translated from C
// structures mostly 1:1), all other data are parsed on-demand.
//
// Event will be passed to the user EventCallback. It's invalid to use Event
// methods outside of an EventCallback.
type Event struct {
	Header EventHeader `json:"header"`
	Info   interface{} `json:"info"`
	Ext    interface{} `json:"ext"`
}

// NewEvent create new event instance.
func NewEvent(r C.PEVENT_RECORD) *Event {
	if r == nil {
		return nil
	}

	return &Event{
		Header: parseEventHeader(r.EventHeader), // different version for xp and vista+
		Info:   parseEventInfo(r),
		Ext:    parseExtendedInfo(r),
	}
}

// Free data.
func (e *Event) Free() {
	if e == nil {
		return
	}
}

// EventHeader contains an information that is common for every ETW event
// record.
//
// EventHeader fields is self-descriptive. If you need more info refer to the
// original struct docs:
// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
type EventHeader struct {
	Descriptor EventDescriptor `json:"descriptor"`

	ThreadID      uint32        `json:"thread_id"`
	ProcessID     uint32        `json:"process_id"`
	TimeStamp     time.Time     `json:"ts"`
	ProviderID    provider.GUID `json:"provider_guid"`
	ActivityID    provider.GUID `json:"activity_guid"`
	Flags         uint16        `json:"flags"`
	KernelTime    uint32        `json:"kernel_time"`
	UserTime      uint32        `json:"user_time"`
	ProcessorTime uint64        `json:"processor_time"`
}

func guidToGo(guid C.GUID) provider.GUID {
	var data4 [8]byte
	for i := range data4 {
		data4[i] = byte(guid.Data4[i])
	}
	return provider.GUID{
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

// EventDescriptor contains low-level metadata that defines received event.
// Most of fields could be used to refine events filtration.
//
// For detailed information about fields values refer to EVENT_DESCRIPTOR docs:
// https://docs.microsoft.com/ru-ru/windows/win32/api/evntprov/ns-evntprov-event_descriptor
type EventDescriptor struct {
	ID      uint16 `json:"id"`
	Version uint8  `json:"version"`
	Channel uint8  `json:"channel"`
	Level   uint8  `json:"level"`
	OpCode  uint8  `json:"op_code"`
	Task    uint16 `json:"task"`
	Keyword uint64 `json:"keyword"`
}

func parseEventDescriptor(descriptor C.EVENT_DESCRIPTOR) EventDescriptor {
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
