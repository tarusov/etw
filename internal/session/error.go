// +build windows

package session

import "fmt"

// ExistsError is returned by NewSession if the session name is already taken.
//
// Having ExistsError you have an option to force kill the session:
//
//		var exists etw.ExistsError
//		s, err = etw.NewSession(s.guid, etw.WithName(sessionName))
//		if errors.As(err, &exists) {
//			err = etw.KillSession(exists.SessionName)
//		}
//
type ExistsError struct{ SessionName string }

func (e ExistsError) Error() string {
	return fmt.Sprintf("session %q already exist", e.SessionName)
}
