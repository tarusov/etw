// +build windows

package session

/*
#include <windows.h>
*/
import "C"

// EnableProperty enables a property of a provider session is subscribing for.
//
// For more info about available properties check original API reference:
// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
type EnableProperty C.ULONG

//nolint:golint,stylecheck // We keep original names to underline that it's an external constants.
const (
	// Include in the ExtendedEventInfo the security identifier (SID) of the user.
	EVENT_ENABLE_PROPERTY_SID = EnableProperty(0x001)

	// Include in the ExtendedEventInfo the terminal session identifier.
	EVENT_ENABLE_PROPERTY_TS_ID = EnableProperty(0x002)

	// Include in the ExtendedEventInfo a call stack trace for events written
	// using EventWrite.
	EVENT_ENABLE_PROPERTY_STACK_TRACE = EnableProperty(0x004)

	// Filters out all events that do not have a non-zero keyword specified.
	// By default events with 0 keywords are accepted.
	EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0 = EnableProperty(0x010)

	// Filters out all events that are either marked as an InPrivate event or
	// come from a process that is marked as InPrivate. InPrivate implies that
	// the event or process contains some data that would be considered private
	// or personal. It is up to the process or event to designate itself as
	// InPrivate for this to work.
	EVENT_ENABLE_PROPERTY_EXCLUDE_INPRIVATE = EnableProperty(0x200)
)
