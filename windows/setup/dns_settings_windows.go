//go:build windows

package main

// The SetInterfaceDnsSettings calling-convention handling follows the
// MIT-licensed WireGuard for Windows winipcfg implementation:
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

import (
	"errors"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	dnsInterfaceSettingsVersion1       = 1
	dnsInterfaceSettingsFlagIPv6       = 0x0001
	dnsInterfaceSettingsFlagNameServer = 0x0002
)

type dnsInterfaceSettings struct {
	Version             uint32
	_                   [4]byte
	Flags               uint64
	Domain              *uint16
	NameServer          *uint16
	SearchList          *uint16
	RegistrationEnabled uint32
	RegisterAdapterName uint32
	EnableLLMNR         uint32
	QueryAdapterName    uint32
	ProfileNameServer   *uint16
}

var procSetInterfaceDNSSettings = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SetInterfaceDnsSettings")

func callSetInterfaceDNSSettings(guid windows.GUID, settings *dnsInterfaceSettings) error {
	if err := procSetInterfaceDNSSettings.Find(); err != nil {
		return err
	}
	var result uintptr
	switch runtime.GOARCH {
	case "amd64":
		// A 16-byte GUID passed by value is represented by reference in the
		// Windows x64 ABI.
		result, _, _ = procSetInterfaceDNSSettings.Call(
			uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(settings)))
	case "arm64":
		// The Windows ARM64 ABI passes the GUID in two 64-bit integer words.
		words := *(*[2]uintptr)(unsafe.Pointer(&guid))
		result, _, _ = procSetInterfaceDNSSettings.Call(
			words[0], words[1], uintptr(unsafe.Pointer(settings)))
	default:
		return errors.New("неподдерживаемая архитектура Windows")
	}
	runtime.KeepAlive(guid)
	runtime.KeepAlive(settings)
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}

// setNativeDNS uses the Windows 10 per-interface DNS API. An empty server list
// restores automatic DNS for that address family. It deliberately changes only
// name servers and preserves search suffixes and the other adapter properties.
func setNativeDNS(guidText string, ipv6 bool, servers []string) error {
	guid, err := windows.GUIDFromString(guidWithBraces(guidText))
	if err != nil {
		return err
	}
	nameServers, err := windows.UTF16PtrFromString(strings.Join(servers, ","))
	if err != nil {
		return err
	}
	flags := uint64(dnsInterfaceSettingsFlagNameServer)
	if ipv6 {
		flags |= dnsInterfaceSettingsFlagIPv6
	}
	settings := &dnsInterfaceSettings{
		Version:    dnsInterfaceSettingsVersion1,
		Flags:      flags,
		NameServer: nameServers,
	}
	err = callSetInterfaceDNSSettings(guid, settings)
	runtime.KeepAlive(nameServers)
	return err
}
