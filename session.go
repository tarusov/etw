//+build windows

package etw

import (
	"github.com/tarusov/etw/internal/session"
)

// Session interface defines are module.
type Session interface {
	Process(cb func([]byte)) error // Callback is JSON parser.
	Close() error
}

// SessionOptions defines session options.
type SessionOptions struct {
	ProviderName string
	KernelArgs   []string
	TraceLevel   string
}

// NewSession create new event tracing session.
func NewSession(opts *SessionOptions) (Session, error) {
	return session.New(opts.ProviderName, opts.TraceLevel, opts.KernelArgs)
}
