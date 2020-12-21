// +build windows

#include <windows.h>
#include <evntcons.h>

TRACEHANDLE OpenTraceHelper(LPWSTR name, PVOID ctx);