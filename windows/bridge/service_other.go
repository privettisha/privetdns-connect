//go:build !windows

package main

import "errors"

func runWindowsService(_ string, _ func() (*bridgeRuntime, error)) error {
	return errors.New("Windows service mode is unavailable")
}
