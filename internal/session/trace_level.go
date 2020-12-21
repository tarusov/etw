// +build windows

package session

/*
	#include <windows.h>
*/
import "C"
import (
	"fmt"
	"strings"
)

// TraceLevel represents provider-defined value that specifies the level of
// detail included in the event. Higher levels imply that you get lower
// levels as well.
type traceLevel C.UCHAR

//nolint:golint,stylecheck // We keep original names to underline that it's an external constants.
const (
	TRACE_LEVEL_CRITICAL    = traceLevel(1)
	TRACE_LEVEL_ERROR       = traceLevel(2)
	TRACE_LEVEL_WARNING     = traceLevel(3)
	TRACE_LEVEL_INFORMATION = traceLevel(4)
	TRACE_LEVEL_VERBOSE     = traceLevel(5)
)

// parseTraceLevel return provider tracing level.
func parseTraceLevel(v string) (traceLevel, error) {
	v = strings.ToLower(v)
	switch v {
	case "information":
		return TRACE_LEVEL_INFORMATION, nil
	case "verbose":
		return TRACE_LEVEL_VERBOSE, nil
	case "warning":
		return TRACE_LEVEL_WARNING, nil
	case "error":
		return TRACE_LEVEL_ERROR, nil
	case "critical":
		return TRACE_LEVEL_CRITICAL, nil
	default:
		return 0, fmt.Errorf("unknown trace level %q", v)
	}
}
