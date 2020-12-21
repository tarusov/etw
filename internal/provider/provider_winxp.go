// +build windows
// +build winxp

package provider

import (
	"bufio"
	"bytes"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

const (
	logmanExecPath     = "c:\\windows\\system32\\logman.exe"
	logmanArgQuery     = "query"
	logmanArgProviders = "providers"
)

// EnumerateProviders returns a mapping of provider name to guid.
//
// For enumerating providers by a command line use:
// `logman query providers`.
func EnumerateProviders() (map[string]GUID, error) {
	out, err := exec.Command(logmanExecPath, logmanArgQuery, logmanArgProviders).Output()
	if err != nil {
		return nil, err
	}

	return parseProvidersList(bytes.NewReader(out))
}

// parse `logman query providers` cmd output.
func parseProvidersList(r io.Reader) (map[string]GUID, error) {
	const headerOffset = 2

	var (
		sc        = bufio.NewScanner(r)
		providers = make(map[string]GUID)
	)

	var i int
	for sc.Scan() {
		i++

		if i <= headerOffset {
			continue
		}

		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			break
		}

		last := len(fields) - 1
		name := strings.Join(fields[:last], " ")

		guid, err := ParseGUID(fields[last])
		if err != nil {
			continue
		}

		providers[strings.ToLower(name)] = guid
	}

	err := sc.Err()
	if err != nil {
		return nil, err
	}

	return providers, nil
}

// EnumerateProviderKeywords returns a mapping of a keyword name to a keyword
// value.
//
// For listing keywords (for "Windows Kernel Trace" provider) by a command line
// use: `logman query providers "Windows Kernel Trace"`.
func EnumerateProviderKeywords(providerGUID GUID) (map[string]uint64, error) {
	out, err := exec.Command(logmanExecPath, logmanArgQuery, logmanArgProviders, providerGUID.String()).Output()
	if err != nil {
		return nil, err
	}

	return parseProviderKeywordsList(bytes.NewReader(out))
}

// parse `logman query providers {GUID}` cmd output.
func parseProviderKeywordsList(r io.Reader) (map[string]uint64, error) {
	const headerOffset = 6

	var (
		sc       = bufio.NewScanner(r)
		keywords = make(map[string]uint64)
	)

	var i int
	for sc.Scan() {
		i++

		if i <= headerOffset {
			continue
		}

		text := sc.Text()

		fields := strings.Fields(text)
		if len(fields) < 2 {
			break
		}

		value, err := strconv.ParseUint(fields[0], 0, 64)
		if err != nil {
			continue
		}

		name := fields[1]

		keywords[name] = value
	}

	err := sc.Err()
	if err != nil {
		return nil, err
	}

	return keywords, nil
}
