// +build windows
// +build winxp

package session

/*
#include "session_winxp.h"
*/
import "C"

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

func parseEventInfo(_ C.PEVENT_RECORD) interface{} {
	return nil
}

// TODO: parse other fields for event.
func parseExtendedInfo(_ C.PEVENT_RECORD) interface{} {
	return nil
}
