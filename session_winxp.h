// +build windows,winxp

// MinGW headers are always restricted to the lowest possible Windows version,
// so specify Windows XP.
#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WINXP

#include <windows.h>
#include <evntcons.h>

// OpenTraceHelper helps to access EVENT_TRACE_LOGFILEW union fields and pass
// pointer to C not warning CGO checker.
TRACEHANDLE OpenTraceHelper(LPWSTR name, PVOID ctx);

// Event header unions getters.
LONGLONG GetTimeStamp(EVENT_HEADER header);
ULONG GetKernelTime(EVENT_HEADER header);
ULONG GetUserTime(EVENT_HEADER header);
ULONG64 GetProcessorTime(EVENT_HEADER header);

// Helpers for extended data parsing.
USHORT GetExtType(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int idx);
ULONGLONG GetDataPtr(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int idx);
USHORT GetDataSize(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int idx);
ULONG GetAddress32(PEVENT_EXTENDED_ITEM_STACK_TRACE32 trace32, int idx);
ULONGLONG GetAddress64(PEVENT_EXTENDED_ITEM_STACK_TRACE64 trace64, int idx);
