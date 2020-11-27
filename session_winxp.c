// +build windows,winxp

#include "session_winxp.h"
#include <in6addr.h>

// handleEvent is exported from Go to CGO. Unfortunately CGO can't vary calling
// convention of exported functions (or we don't know da way), so wrap the Go's
// callback with a stdcall one.
extern void handleEvent(PEVENT_RECORD e);

void WINAPI stdcallHandleEvent(PEVENT_RECORD e) {
    handleEvent(e);
}

// OpenTraceHelper helps to access EVENT_TRACE_LOGFILEW union fields and pass
// pointer to C not warning CGO checker.
TRACEHANDLE OpenTraceHelper(LPWSTR name, PVOID ctx) {
    EVENT_TRACE_LOGFILEW trace = {0};
    trace.LoggerName = name;
    trace.Context = ctx;
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = stdcallHandleEvent;

    return OpenTraceW(&trace);
}

LONGLONG GetTimeStamp(EVENT_HEADER header) {
    return header.TimeStamp.QuadPart;
}

ULONG GetKernelTime(EVENT_HEADER header) {
    return header.KernelTime;
}

ULONG GetUserTime(EVENT_HEADER header) {
    return header.UserTime;
}

ULONG64 GetProcessorTime(EVENT_HEADER header) {
    return header.ProcessorTime;
}

USHORT GetExtType(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int i) {
    return extData[i].ExtType;
}

ULONGLONG GetDataPtr(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int i) {
    return extData[i].DataPtr;
}

USHORT GetDataSize(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int i) {
     return extData[i].DataSize;
}

ULONG GetAddress32(PEVENT_EXTENDED_ITEM_STACK_TRACE32 trace32, int j) {
    return trace32->Address[j];
}

ULONGLONG GetAddress64(PEVENT_EXTENDED_ITEM_STACK_TRACE64 trace64, int j) {
   return trace64->Address[j];
}
