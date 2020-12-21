// +build windows
// +build 386

package winapi

import (
	"unsafe"
)

// ULONGLONG defines a struct containing a pointer. The struct is guaranteed to
// be 64 bits, regardless of the actual size of a pointer on the platform. This
// is intended for use with certain Windows APIs that expect a pointer as a
// ULONGLONG.
//
//nolint:golint,stylecheck // We keep original names to underline that it's an external constants.
type ULONGLONG struct {
	Pointer unsafe.Pointer
	_       uint32
}
