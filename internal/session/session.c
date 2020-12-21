#include "session.h"

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