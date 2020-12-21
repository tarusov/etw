// +build windows

package provider

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// GUID is a Go-copy of windows GUID struct.
// See: https://docs.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid.
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func (g *GUID) String() string {
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%X", g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1], g.Data4[2:])
}

func (g *GUID) MarshalJSON() ([]byte, error) {
	stamp := fmt.Sprintf("\"%s\"", g.String())
	return []byte(stamp), nil
}

// ParseGUID return guid from string.
func ParseGUID(s string) (GUID, error) {
	var guid GUID
	switch len(s) {
	// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	case 36:

	// {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
	case 36 + 2:
		s = s[1:37]
	default:
		return guid, fmt.Errorf("invalid guid length: %d", len(s))
	}
	// s is now at least 36 bytes long
	// it must be of the form  xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return guid, errors.New("invalid guid format")
	}

	d1, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return guid, fmt.Errorf("parse guid failed: %v", err)
	}
	guid.Data1 = uint32(d1)

	d2, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return guid, fmt.Errorf("parse guid failed: %v", err)
	}
	guid.Data2 = uint16(d2)

	d3, err := strconv.ParseUint(parts[2], 16, 16)
	if err != nil {
		return guid, fmt.Errorf("parse guid failed: %v", err)
	}
	guid.Data3 = uint16(d3)

	_, err = hex.Decode(guid.Data4[:], []byte(parts[3]+parts[4]))

	return guid, err
}

// ParseName converts provider name into guid.
func ParseName(providerName string) (guid GUID, err error) {
	providerName = strings.TrimSpace(strings.ToLower(providerName))

	if strings.HasPrefix(providerName, "{") {
		return ParseGUID(providerName)
	}

	providers, err := EnumerateProviders()
	if err != nil {
		return GUID{}, fmt.Errorf("failed enumerate providers: %v", err)
	}

	pGUID, ok := providers[providerName]
	if !ok {
		return GUID{}, fmt.Errorf("unknown provider name: %q", providerName)
	}

	return pGUID, nil
}
