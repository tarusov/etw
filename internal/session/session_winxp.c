// +build windows
// +build winxp

#include "session_winxp.h"

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
