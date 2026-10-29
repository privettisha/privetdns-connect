package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	unicodeutf16 "unicode/utf16"
	"unicode/utf8"
)

var personalDoHPath = regexp.MustCompile(`^/dns-query/device/[A-Za-z0-9_-]{40,64}$`)
var nrptDomain = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var nrptRule = regexp.MustCompile(`^PrivetDNS-[0-9a-f]{24}$`)
var adapterGUID = regexp.MustCompile(`(?i)^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$`)

var ordinaryFallbackDNS = []string{
	"1.1.1.1", "8.8.8.8",
	"2606:4700:4700::1111", "2001:4860:4860::8888",
}

type dnsFamilyState struct {
	Mode    string   `json:"mode"`
	Servers []string `json:"servers"`
}

type adapterState struct {
	GUID        string         `json:"guid"`
	Name        string         `json:"name"`
	IfIndex     uint32         `json:"if_index"`
	IPv6Enabled bool           `json:"ipv6_enabled"`
	IPv4        dnsFamilyState `json:"ipv4"`
	IPv6        dnsFamilyState `json:"ipv6"`
}

type savedState struct {
	Schema           int          `json:"schema"`
	Adapter          adapterState `json:"adapter"`
	TaskCommand      string       `json:"task_command,omitempty"`
	TaskArguments    string       `json:"task_arguments,omitempty"`
	ServiceCommand   string       `json:"service_command,omitempty"`
	ServiceArguments []string     `json:"service_arguments,omitempty"`
	NRPTRules        []string     `json:"nrpt_rules,omitempty"`
}

func parseNRPTDomains(data []byte) ([]string, error) {
	if len(data) == 0 || len(data) > 256*1024 {
		return nil, errors.New("список доменов PrivetDNS повреждён")
	}
	result := make([]string, 0, 512)
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		value := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(line, "\r")))
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		if len(value) > 253 || !nrptDomain.MatchString(value) || seen[value] {
			return nil, errors.New("список доменов PrivetDNS повреждён")
		}
		seen[value] = true
		result = append(result, value)
		if len(result) > 2000 {
			return nil, errors.New("список доменов PrivetDNS слишком большой")
		}
	}
	if len(result) == 0 {
		return nil, errors.New("список доменов PrivetDNS пуст")
	}
	return result, nil
}

func nrptRuleName(domain string) string {
	sum := sha256.Sum256([]byte(domain))
	return "PrivetDNS-" + hex.EncodeToString(sum[:12])
}

func validNRPTRuleName(value string) bool {
	return nrptRule.MatchString(value)
}

func validAdapterGUID(value string) bool {
	return adapterGUID.MatchString(value)
}

func legacyFamily(mode string, servers []string, family int, enabled bool) (dnsFamilyState, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	normalized := normalizeServers(servers, family)
	if mode == "automatic" {
		return dnsFamilyState{Mode: mode, Servers: normalized}, nil
	}
	if mode == "static" && (len(normalized) != 0 || (family == 6 && !enabled)) {
		return dnsFamilyState{Mode: mode, Servers: normalized}, nil
	}
	return dnsFamilyState{}, errors.New("сохранённая конфигурация DNS повреждена")
}

func validatePersonalURL(raw string) (string, error) {
	if raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\r\n\t ") {
		return "", errors.New("в ссылке есть пробелы или лишние символы")
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "https" || u.Hostname() != "dns.privetdns.ru" || u.Port() != "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return "", errors.New("вставьте персональную DoH-ссылку из личного кабинета")
	}
	if !personalDoHPath.MatchString(u.EscapedPath()) {
		return "", errors.New("это не персональная ссылка устройства PrivetDNS")
	}
	return u.String(), nil
}

func normalizeIPList(values []string, family int, allowLoopback bool) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		value = strings.TrimSpace(value)
		ip := net.ParseIP(value)
		if ip == nil || (!allowLoopback && ip.IsLoopback()) || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			continue
		}
		if family == 4 && ip.To4() == nil {
			continue
		}
		if family == 6 && ip.To4() != nil {
			continue
		}
		normalized := ip.String()
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}
	return result
}

func normalizeServers(values []string, family int) []string {
	return normalizeIPList(values, family, false)
}

func normalizeAdapterServers(values []string, family int) []string {
	return normalizeIPList(values, family, true)
}

func ordinaryResolvers(ipv4, ipv6 []string) []string {
	values := append(append([]string{}, normalizeServers(ipv4, 4)...), normalizeServers(ipv6, 6)...)
	values = append(values, ordinaryFallbackDNS...)
	result := make([]string, 0, 8)
	seen := make(map[string]bool)
	for _, value := range values {
		ip := net.ParseIP(value)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			continue
		}
		normalized := ip.String()
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, normalized)
		if len(result) == 8 {
			break
		}
	}
	return result
}

func sameFamily(a, b dnsFamilyState) bool {
	if a.Mode != b.Mode {
		return false
	}
	if a.Mode == "automatic" {
		return true
	}
	if len(a.Servers) != len(b.Servers) {
		return false
	}
	for i := range a.Servers {
		if a.Servers[i] != b.Servers[i] {
			return false
		}
	}
	return true
}

func isOurLoopback(state dnsFamilyState, address string) bool {
	return state.Mode == "static" && len(state.Servers) == 1 && state.Servers[0] == address
}

func isOnlyDNS(servers []string, address string) bool {
	return len(servers) == 1 && servers[0] == address
}

func loopbackDNSApplied(ipv4, ipv6 []string, requireIPv6 bool) bool {
	return isOnlyDNS(ipv4, "127.0.0.1") && (!requireIPv6 || isOnlyDNS(ipv6, "::1"))
}

// Windows network drivers can briefly return a stale adapter DNS list after
// accepting the change. A successful lookup through the Windows DNS Client is
// also authoritative because that is the resolver applications actually use.
func dnsInstallVerified(adapterApplied, systemResolverWorks bool) bool {
	return adapterApplied || systemResolverWorks
}

func decodeCommandOutput(data []byte) string {
	if len(data) >= 2 {
		utf16LE := data[0] == 0xff && data[1] == 0xfe
		if !utf16LE && len(data) >= 8 {
			zeroes := 0
			for index := 1; index < len(data) && index < 128; index += 2 {
				if data[index] == 0 {
					zeroes++
				}
			}
			utf16LE = zeroes >= 3
		}
		if utf16LE {
			start := 0
			if data[0] == 0xff && data[1] == 0xfe {
				start = 2
			}
			units := make([]uint16, 0, (len(data)-start)/2)
			for index := start; index+1 < len(data); index += 2 {
				units = append(units, binary.LittleEndian.Uint16(data[index:index+2]))
			}
			return string(unicodeutf16.Decode(units))
		}
	}
	decoded := string(data)
	if !utf8.ValidString(decoded) {
		return ""
	}
	return decoded
}
