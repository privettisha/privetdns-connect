//go:build windows

package main

import (
	_ "embed"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed payload/privetdns-bridge.exe
var bridgePayload []byte

//go:embed payload/smartdns-domains.txt
var domainsPayload []byte

const (
	taskName            = "PrivetDNS-Windows-Bridge"
	installDirName      = "PrivetDNS-Windows-Bridge"
	setupVersion        = "3.1.2"
	stateName           = "state.json"
	configName          = "config.json"
	runtimeName         = "privetdns-bridge.exe"
	domainsName         = "smartdns-domains.txt"
	legacyNativeDirName = "PrivetDNS-Native"
	legacyStubDirName   = "PrivetDNS-Personal-LocalStub"
	legacyStubTaskName  = "PrivetDNS-Personal-LocalStub"
	legacyNativeServer  = "31.76.244.138"
)

const nrptRegistryRoot = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`

type adapterInfo struct {
	GUID        string
	Name        string
	IfIndex     uint32
	IfType      uint32
	OperStatus  uint32
	IPv6Enabled bool
	DNSv4       []string
	DNSv6       []string
}

type taskXML struct {
	Principals struct {
		Principal struct {
			UserID string `xml:"UserId"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Actions struct {
		Exec struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

type powerShellAdapterState struct {
	GUID        string   `json:"Guid"`
	IPv6Enabled bool     `json:"IPv6Enabled"`
	IPv4Mode    string   `json:"IPv4Mode"`
	IPv4Servers []string `json:"IPv4Servers"`
	IPv6Mode    string   `json:"IPv6Mode"`
	IPv6Servers []string `json:"IPv6Servers"`
}

type powerShellSavedState struct {
	Schema        int                    `json:"Schema"`
	Adapter       powerShellAdapterState `json:"Adapter"`
	TaskArguments string                 `json:"TaskArguments"`
}

type legacyNativeSavedState struct {
	Schema  int    `json:"Schema"`
	Server  string `json:"Server"`
	Adapter struct {
		GUID    string   `json:"Guid"`
		Mode    string   `json:"Mode"`
		Servers []string `json:"Servers"`
	} `json:"Adapter"`
}

type legacyStubSavedState struct {
	Schema  int `json:"Schema"`
	Adapter struct {
		GUID        string   `json:"Guid"`
		IPv4Mode    string   `json:"IPv4Mode"`
		IPv4Servers []string `json:"IPv4Servers"`
	} `json:"Adapter"`
	Python        string `json:"Python"`
	TaskArguments string `json:"TaskArguments"`
}

func convertPowerShellState(data []byte, runtimeFile, configFile string) (savedState, error) {
	var old powerShellSavedState
	if json.Unmarshal(data, &old) != nil || old.Schema != 1 || !validAdapterGUID(old.Adapter.GUID) {
		return savedState{}, errors.New("сохранённая конфигурация PrivetDNS повреждена")
	}
	expected := `--config "` + configFile + `" --port 53`
	if old.TaskArguments != expected && old.TaskArguments != expected+" --ipv6" {
		return savedState{}, errors.New("сохранённая конфигурация PrivetDNS повреждена")
	}
	ipv4, err := legacyFamily(old.Adapter.IPv4Mode, old.Adapter.IPv4Servers, 4, true)
	if err != nil {
		return savedState{}, err
	}
	ipv6, err := legacyFamily(old.Adapter.IPv6Mode, old.Adapter.IPv6Servers, 6, old.Adapter.IPv6Enabled)
	if err != nil {
		return savedState{}, err
	}
	return savedState{
		Schema: 1,
		Adapter: adapterState{
			GUID: old.Adapter.GUID, IPv6Enabled: old.Adapter.IPv6Enabled,
			IPv4: ipv4, IPv6: ipv6,
		},
		TaskCommand: runtimeFile, TaskArguments: old.TaskArguments,
	}, nil
}

func paths() (dir, state, config, runtimePath, domains string, err error) {
	programData := strings.TrimSpace(os.Getenv("ProgramData"))
	if programData == "" || !filepath.IsAbs(programData) {
		return "", "", "", "", "", errors.New("не найдена системная папка ProgramData")
	}
	dir = filepath.Join(programData, installDirName)
	return dir, filepath.Join(dir, stateName), filepath.Join(dir, configName),
		filepath.Join(dir, runtimeName), filepath.Join(dir, domainsName), nil
}

func runHiddenLimit(limit int, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(decodeCommandOutput(output))
	if len(text) > limit {
		if err == nil {
			return "", errors.New("системная команда вернула слишком большой ответ")
		}
		text = string([]rune(text)[:min(len([]rune(text)), limit/2)])
	}
	if err != nil {
		if text == "" {
			return "", err
		}
		return text, fmt.Errorf("%w: %s", err, text)
	}
	return text, nil
}

func runHidden(name string, args ...string) (string, error) {
	return runHiddenLimit(1200, name, args...)
}

func taskExistsNamed(name string) bool {
	_, err := runHidden("schtasks.exe", "/Query", "/TN", name)
	return err == nil
}

func taskExists() bool { return taskExistsNamed(taskName) }

func readTaskNamed(name string) (*taskXML, error) {
	output, err := runHiddenLimit(256*1024, "schtasks.exe", "/Query", "/TN", name, "/XML")
	if err != nil {
		return nil, err
	}
	if start := strings.Index(output, "<Task"); start >= 0 {
		output = output[start:]
	}
	var task taskXML
	if err := xml.Unmarshal([]byte(output), &task); err != nil {
		return nil, errors.New("не удалось проверить системную задачу PrivetDNS")
	}
	return &task, nil
}

func readTask() (*taskXML, error) { return readTaskNamed(taskName) }

func deleteTaskNamed(name string) error {
	if !taskExistsNamed(name) {
		return nil
	}
	_, _ = runHidden("schtasks.exe", "/End", "/TN", name)
	if _, err := runHidden("schtasks.exe", "/Delete", "/TN", name, "/F"); err != nil {
		return err
	}
	return nil
}

func adapters() ([]adapterInfo, error) {
	size := uint32(15 * 1024)
	for attempt := 0; attempt < 3; attempt++ {
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_GATEWAYS, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("не удалось получить сетевые адаптеры: %w", err)
		}
		var result []adapterInfo
		for current := first; current != nil; current = current.Next {
			info := adapterInfo{
				GUID:        windows.BytePtrToString(current.AdapterName),
				Name:        windows.UTF16PtrToString(current.FriendlyName),
				IfIndex:     current.IfIndex,
				IfType:      current.IfType,
				OperStatus:  current.OperStatus,
				IPv6Enabled: current.Flags&0x100 != 0 && current.Ipv6IfIndex != 0,
			}
			for dns := current.FirstDnsServerAddress; dns != nil; dns = dns.Next {
				ip := dns.Address.IP()
				if ip == nil {
					continue
				}
				if ip.To4() != nil {
					info.DNSv4 = append(info.DNSv4, ip.String())
				} else {
					info.DNSv6 = append(info.DNSv6, ip.String())
				}
			}
			info.DNSv4 = normalizeAdapterServers(info.DNSv4, 4)
			info.DNSv6 = normalizeAdapterServers(info.DNSv6, 6)
			result = append(result, info)
		}
		runtime.KeepAlive(buffer)
		return result, nil
	}
	return nil, errors.New("Windows вернула слишком большой список сетевых адаптеров")
}

func bestPhysicalAdapter() (adapterInfo, error) {
	var index uint32
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{1, 1, 1, 1}}, &index); err != nil {
		return adapterInfo{}, errors.New("не найдено активное подключение к интернету")
	}
	items, err := adapters()
	if err != nil {
		return adapterInfo{}, err
	}
	for _, item := range items {
		if item.IfIndex != index {
			continue
		}
		if item.OperStatus != windows.IfOperStatusUp {
			return adapterInfo{}, errors.New("основное сетевое подключение не активно")
		}
		if item.IfType != windows.IF_TYPE_ETHERNET_CSMACD && item.IfType != windows.IF_TYPE_IEEE80211 {
			return adapterInfo{}, errors.New("сейчас основной маршрут идёт через VPN или виртуальный адаптер; отключите VPN на время установки")
		}
		return item, nil
	}
	return adapterInfo{}, errors.New("не удалось сопоставить основной маршрут с сетевым адаптером")
}

func adapterByGUID(guid string) (adapterInfo, error) {
	items, err := adapters()
	if err != nil {
		return adapterInfo{}, err
	}
	for _, item := range items {
		if strings.EqualFold(strings.Trim(item.GUID, "{}"), strings.Trim(guid, "{}")) {
			return item, nil
		}
	}
	return adapterInfo{}, errors.New("сетевое подключение, на которое был установлен PrivetDNS, не найдено")
}

func staticNameServers(guid string, ipv6 bool) (string, error) {
	service := "Tcpip"
	if ipv6 {
		service = "Tcpip6"
	}
	path := `SYSTEM\CurrentControlSet\Services\` + service + `\Parameters\Interfaces\` + guidWithBraces(guid)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer key.Close()
	value, _, err := key.GetStringValue("NameServer")
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	return strings.TrimSpace(value), err
}

func guidWithBraces(value string) string {
	value = strings.Trim(value, "{}")
	return "{" + value + "}"
}

func snapshot(info adapterInfo) (adapterState, error) {
	static4, err := staticNameServers(info.GUID, false)
	if err != nil {
		return adapterState{}, fmt.Errorf("не удалось прочитать настройки IPv4 DNS: %w", err)
	}
	static6, err := staticNameServers(info.GUID, true)
	if err != nil {
		return adapterState{}, fmt.Errorf("не удалось прочитать настройки IPv6 DNS: %w", err)
	}
	state := adapterState{GUID: info.GUID, Name: info.Name, IfIndex: info.IfIndex, IPv6Enabled: info.IPv6Enabled}
	state.IPv4, err = snapshotDNSFamily(static4, info.DNSv4, 4, true)
	if err != nil {
		return adapterState{}, err
	}
	state.IPv6, err = snapshotDNSFamily(static6, info.DNSv6, 6, info.IPv6Enabled)
	if err != nil {
		return adapterState{}, err
	}
	return state, nil
}

func plannedNRPTRules(domains []string) []string {
	rules := make([]string, len(domains))
	for index, domain := range domains {
		rules[index] = nrptRuleName(domain)
	}
	return rules
}

func installNRPTRules(domains, rules []string) error {
	if len(domains) == 0 || len(domains) != len(rules) {
		return errors.New("список правил Windows повреждён")
	}
	created := make([]string, 0, len(rules))
	for index, rule := range rules {
		if !validNRPTRuleName(rule) || rule != nrptRuleName(domains[index]) {
			_ = deleteNRPTRules(created)
			return errors.New("список правил Windows повреждён")
		}
		path := nrptRegistryRoot + `\` + rule
		key, existed, err := registry.CreateKey(registry.LOCAL_MACHINE, path,
			registry.SET_VALUE|registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			_ = deleteNRPTRules(created)
			return fmt.Errorf("не удалось создать правило DNS Windows: %w", err)
		}
		if existed {
			key.Close()
			_ = deleteNRPTRules(created)
			return errors.New("найдено постороннее правило с именем PrivetDNS; установка остановлена")
		}
		created = append(created, rule)
		err = key.SetStringsValue("Name", []string{"." + domains[index]})
		if err == nil {
			err = key.SetStringValue("GenericDNSServers", "127.0.0.1")
		}
		if err == nil {
			err = key.SetDWordValue("ConfigOptions", 8)
		}
		if err == nil {
			err = key.SetDWordValue("Version", 2)
		}
		closeErr := key.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			_ = deleteNRPTRules(created)
			return fmt.Errorf("не удалось записать правило DNS Windows: %w", err)
		}
	}
	refreshDNSPolicy()
	return nil
}

func validateInstalledNRPTRules(rules []string) error {
	if len(rules) == 0 || len(rules) > 2000 {
		return errors.New("сохранённый список правил Windows повреждён")
	}
	seen := make(map[string]bool)
	for _, rule := range rules {
		if !validNRPTRuleName(rule) || seen[rule] {
			return errors.New("сохранённый список правил Windows повреждён")
		}
		seen[rule] = true
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptRegistryRoot+`\`+rule,
			registry.QUERY_VALUE|registry.WOW64_64KEY)
		if errors.Is(err, registry.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("не удалось проверить правило DNS Windows: %w", err)
		}
		names, _, namesErr := key.GetStringsValue("Name")
		server, _, serverErr := key.GetStringValue("GenericDNSServers")
		options, _, optionsErr := key.GetIntegerValue("ConfigOptions")
		version, _, versionErr := key.GetIntegerValue("Version")
		key.Close()
		if namesErr != nil || serverErr != nil || optionsErr != nil || versionErr != nil ||
			len(names) != 1 || !strings.HasPrefix(names[0], ".") ||
			nrptRuleName(strings.TrimPrefix(names[0], ".")) != rule ||
			server != "127.0.0.1" || options != 8 || version != 2 {
			return errors.New("правило PrivetDNS было изменено; автоматическое удаление остановлено")
		}
	}
	return nil
}

func deleteNRPTRules(rules []string) error {
	if len(rules) > 2000 {
		return errors.New("сохранённый список правил Windows повреждён")
	}
	for _, rule := range rules {
		if !validNRPTRuleName(rule) {
			return errors.New("сохранённый список правил Windows повреждён")
		}
	}
	var firstErr error
	for _, rule := range rules {
		err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptRegistryRoot+`\`+rule)
		if err != nil && !errors.Is(err, registry.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	refreshDNSPolicy()
	if firstErr != nil {
		return fmt.Errorf("не удалось удалить правило DNS Windows: %w", firstErr)
	}
	return nil
}

// A failed or interrupted installation can leave NRPT rules and a service but
// lose state.json. Only recover rules whose names and values match our own
// schema-4 policy; never guess the original adapter DNS of older installers.
func orphanedNRPTRules() ([]string, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptRegistryRoot,
		registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("не удалось проверить правила DNS Windows: %w", err)
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(0)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать правила DNS Windows: %w", err)
	}
	rules := make([]string, 0)
	for _, name := range names {
		if strings.HasPrefix(name, "PrivetDNS-") {
			if !validNRPTRuleName(name) {
				return nil, errors.New("найдено неизвестное правило PrivetDNS; восстановление остановлено")
			}
			rules = append(rules, name)
		}
	}
	if len(rules) > 2000 {
		return nil, errors.New("слишком много правил PrivetDNS; восстановление остановлено")
	}
	if len(rules) != 0 {
		if err := validateInstalledNRPTRules(rules); err != nil {
			return nil, err
		}
	}
	return rules, nil
}

func recoverOrphanedInstall(dir, stateFile, configFile, runtimeFile string) (bool, error) {
	if isReparse(dir) || isReparse(stateFile) || isReparse(configFile) || isReparse(runtimeFile) {
		return false, errors.New("папка PrivetDNS была подменена; восстановление остановлено")
	}
	if taskExists() {
		return false, errors.New("найдена старая задача PrivetDNS без файла восстановления; настройки DNS не изменены")
	}
	rules, err := orphanedNRPTRules()
	if err != nil {
		return false, err
	}
	serviceFound, err := servicePresent()
	if err != nil {
		return false, fmt.Errorf("не удалось проверить службу PrivetDNS: %w", err)
	}
	if serviceFound {
		baseArgs := []string{"--service", "--config", configFile, "--port", "53"}
		matches, matchErr := serviceMatches(runtimeFile, baseArgs)
		if matchErr != nil {
			return false, matchErr
		}
		if !matches {
			matches, matchErr = serviceMatches(runtimeFile, append(baseArgs, "--ipv6"))
		}
		if matchErr != nil || !matches {
			return false, errors.New("служба PrivetDNS была изменена; восстановление остановлено")
		}
	}
	// A pre-v3 installation may have changed an adapter DNS, even if NRPT
	// rules happen to exist. Never guess its original DNS without saved state.
	items, err := adapters()
	if err != nil {
		return false, err
	}
	for _, item := range items {
		if item.IfType != windows.IF_TYPE_ETHERNET_CSMACD && item.IfType != windows.IF_TYPE_IEEE80211 {
			continue
		}
		for _, server := range append(item.DNSv4, item.DNSv6...) {
			if server == "127.0.0.1" || server == "::1" {
				return false, errors.New("старый DNS указывает на локальный адрес; без файла восстановления удаление остановлено")
			}
		}
	}
	if len(rules) != 0 {
		if err := deleteNRPTRules(rules); err != nil {
			return false, err
		}
	}
	if serviceFound {
		if err := stopDeleteService(); err != nil {
			return false, fmt.Errorf("правила DNS удалены, но службу удалить не удалось: %w", err)
		}
	}
	if _, err := os.Lstat(dir); err == nil {
		if err := archiveLegacyDirectory(dir); err != nil {
			return false, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	} else if len(rules) == 0 && !serviceFound {
		return false, nil
	}
	return true, nil
}

func refreshDNSPolicy() {
	// Ask the DNS Client to reload the newly written rules and clear its cache.
	// This does not test any external service or make installation depend on it.
	_, _ = runHidden("sc.exe", "control", "Dnscache", "paramchange")
	flushDNS()
}

func isReparse(path string) bool {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attributes, err := windows.GetFileAttributes(pointer)
	return err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func protectDirectory(path string) error {
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	if _, err := runHidden("icacls.exe", path, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"); err != nil {
		return fmt.Errorf("не удалось защитить файлы установки: %w", err)
	}
	return nil
}

func writeExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func setDNS(name string, ipv6 bool, family dnsFamilyState) error {
	protocol := "ipv4"
	if ipv6 {
		protocol = "ipv6"
	}
	base := []string{"interface", protocol, "set", "dnsservers", "name=" + name}
	if family.Mode == "automatic" {
		_, err := runHidden("netsh.exe", append(base, "source=dhcp")...)
		return err
	}
	if family.Mode != "static" || len(family.Servers) == 0 {
		return errors.New("сохранённая конфигурация DNS повреждена")
	}
	if _, err := runHidden("netsh.exe", append(base, "source=static", "address="+family.Servers[0], "register=primary", "validate=no")...); err != nil {
		return err
	}
	for index, server := range family.Servers[1:] {
		args := []string{"interface", protocol, "add", "dnsservers", "name=" + name, "address=" + server, fmt.Sprintf("index=%d", index+2), "validate=no"}
		if _, err := runHidden("netsh.exe", args...); err != nil {
			return err
		}
	}
	return nil
}

func setDNSForAdapter(adapter adapterState, ipv6 bool, family dnsFamilyState) error {
	servers := family.Servers
	if family.Mode == "automatic" {
		servers = nil
	}
	if err := setNativeDNS(adapter.GUID, ipv6, servers); err == nil {
		return nil
	}
	if err := setDNS(adapter.Name, ipv6, family); err == nil {
		return nil
	}
	return setDNS(strconv.FormatUint(uint64(adapter.IfIndex), 10), ipv6, family)
}

func setLoopback(name string, ipv6 bool) error {
	address := "127.0.0.1"
	protocol := "ipv4"
	if ipv6 {
		address, protocol = "::1", "ipv6"
	}
	_, err := runHidden("netsh.exe", "interface", protocol, "set", "dnsservers", "name="+name,
		"source=static", "address="+address, "register=primary", "validate=no")
	return err
}

func setLoopbackForAdapter(adapter adapterState, ipv6 bool) error {
	address := "127.0.0.1"
	if ipv6 {
		address = "::1"
	}
	if err := setNativeDNS(adapter.GUID, ipv6, []string{address}); err == nil {
		return nil
	}
	firstErr := setLoopback(adapter.Name, ipv6)
	if firstErr == nil {
		return nil
	}
	index := strconv.FormatUint(uint64(adapter.IfIndex), 10)
	if err := setLoopback(index, ipv6); err != nil {
		return fmt.Errorf("Windows отклонила настройку по имени (%v) и по индексу: %w", firstErr, err)
	}
	return nil
}

func waitForRestoredDNS(saved adapterState) error {
	var last error
	for attempt := 0; attempt < 30; attempt++ {
		info, err := adapterByGUID(saved.GUID)
		if err != nil {
			last = err
		} else {
			current, snapshotErr := snapshot(info)
			if snapshotErr != nil {
				last = snapshotErr
			} else if !sameFamily(current.IPv4, saved.IPv4) {
				last = errors.New("Windows не восстановила прежний IPv4 DNS")
			} else if saved.IPv6Enabled && !sameFamily(current.IPv6, saved.IPv6) {
				last = errors.New("Windows не восстановила прежний IPv6 DNS")
			} else {
				return nil
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return last
}

func flushDNS() {
	_, _ = runHidden("ipconfig.exe", "/flushdns")
}

func validLegacyPythonPath(path string) bool {
	if path != strings.TrimSpace(path) || !filepath.IsAbs(path) {
		return false
	}
	name := strings.ToLower(filepath.Base(path))
	return name == "python.exe" || name == "python3.exe"
}

func archiveLegacyDirectory(dir string) error {
	if isReparse(dir) {
		return errors.New("папка старой версии PrivetDNS была подменена; автоматическая миграция остановлена")
	}
	base := dir + "-migrated-" + time.Now().Format("20060102-150405")
	destination := base
	for suffix := 1; ; suffix++ {
		if _, err := os.Lstat(destination); errors.Is(err, os.ErrNotExist) {
			break
		}
		destination = base + "-" + strconv.Itoa(suffix)
	}
	if err := os.Rename(dir, destination); err != nil {
		return fmt.Errorf("не удалось убрать файлы старой версии PrivetDNS: %w", err)
	}
	return nil
}

func restoreLegacyIPv4(guid string, family dnsFamilyState, ownedAddress string) error {
	info, err := adapterByGUID(guid)
	if err != nil {
		return err
	}
	current, err := snapshot(info)
	if err != nil {
		return err
	}
	if isOnlyDNS(info.DNSv4, ownedAddress) {
		current.GUID, current.Name, current.IfIndex = info.GUID, info.Name, info.IfIndex
		if err := setDNSForAdapter(current, false, family); err != nil {
			return fmt.Errorf("не удалось восстановить IPv4 DNS старой версии: %w", err)
		}
		flushDNS()
		return nil
	}
	if !sameFamily(current.IPv4, family) {
		return errors.New("IPv4 DNS изменён после старой установки PrivetDNS; автоматическая миграция остановлена")
	}
	return nil
}

func resetStaleLegacyIPv4(ownedAddress string) error {
	info, err := bestPhysicalAdapter()
	if err != nil {
		return err
	}
	if !isOnlyDNS(info.DNSv4, ownedAddress) {
		return nil
	}
	adapter := adapterState{GUID: info.GUID, Name: info.Name, IfIndex: info.IfIndex}
	if err := setDNSForAdapter(adapter, false, dnsFamilyState{Mode: "automatic"}); err != nil {
		return fmt.Errorf("не удалось убрать незавершённую настройку старой версии PrivetDNS: %w", err)
	}
	flushDNS()
	return nil
}

func migrateLegacyNative(dir string) error {
	stateFile := filepath.Join(dir, stateName)
	data, err := os.ReadFile(stateFile)
	if err != nil || len(data) == 0 || len(data) > 64*1024 {
		// A directory without a recovery file is only a stale installation marker.
		// Keep it as an archive rather than deleting unknown recovery data.
		if err := resetStaleLegacyIPv4(legacyNativeServer); err != nil {
			return err
		}
		return archiveLegacyDirectory(dir)
	}
	var state legacyNativeSavedState
	if json.Unmarshal(data, &state) != nil || (state.Schema != 1 && state.Schema != 2) ||
		state.Server != legacyNativeServer || !validAdapterGUID(state.Adapter.GUID) {
		return errors.New("сохранённая конфигурация старой версии PrivetDNS повреждена")
	}
	family, err := legacyFamily(state.Adapter.Mode, state.Adapter.Servers, 4, true)
	if err != nil {
		return err
	}
	if err := restoreLegacyIPv4(state.Adapter.GUID, family, state.Server); err != nil {
		return err
	}
	// Native DoH mappings are harmless after DNS restoration, but remove the
	// exact legacy server mapping when Windows exposes the netsh backend.
	_, _ = runHidden("netsh.exe", "dnsclient", "delete", "encryption", "server="+state.Server, "protocol=doh")
	return archiveLegacyDirectory(dir)
}

func migrateLegacyStub(dir string) error {
	stateFile := filepath.Join(dir, stateName)
	data, err := os.ReadFile(stateFile)
	if err != nil || len(data) == 0 || len(data) > 64*1024 {
		if taskExistsNamed(legacyStubTaskName) {
			task, taskErr := readTaskNamed(legacyStubTaskName)
			if taskErr != nil || !validLegacyPythonPath(strings.TrimSpace(task.Actions.Exec.Command)) ||
				!strings.Contains(strings.ToLower(task.Actions.Exec.Arguments), strings.ToLower(dir)) ||
				!strings.EqualFold(strings.TrimSpace(task.Principals.Principal.UserID), "S-1-5-18") {
				return errors.New("задача старой версии PrivetDNS была изменена; автоматическая миграция остановлена")
			}
			if err := deleteTaskNamed(legacyStubTaskName); err != nil {
				return fmt.Errorf("не удалось удалить автозапуск старой версии PrivetDNS: %w", err)
			}
		}
		if err := resetStaleLegacyIPv4("127.0.0.1"); err != nil {
			return err
		}
		return archiveLegacyDirectory(dir)
	}
	var state legacyStubSavedState
	if json.Unmarshal(data, &state) != nil || state.Schema != 1 || !validAdapterGUID(state.Adapter.GUID) ||
		!validLegacyPythonPath(state.Python) || !strings.Contains(strings.ToLower(state.TaskArguments), strings.ToLower(dir)) {
		return errors.New("сохранённая конфигурация старой версии PrivetDNS повреждена")
	}
	family, err := legacyFamily(state.Adapter.IPv4Mode, state.Adapter.IPv4Servers, 4, true)
	if err != nil {
		return err
	}
	if err := restoreLegacyIPv4(state.Adapter.GUID, family, "127.0.0.1"); err != nil {
		return err
	}
	if taskExistsNamed(legacyStubTaskName) {
		task, taskErr := readTaskNamed(legacyStubTaskName)
		if taskErr != nil || !strings.EqualFold(strings.TrimSpace(task.Actions.Exec.Command), state.Python) ||
			strings.TrimSpace(task.Actions.Exec.Arguments) != state.TaskArguments ||
			!strings.EqualFold(strings.TrimSpace(task.Principals.Principal.UserID), "S-1-5-18") {
			return errors.New("задача старой версии PrivetDNS была изменена; автоматическая миграция остановлена")
		}
		if err := deleteTaskNamed(legacyStubTaskName); err != nil {
			return fmt.Errorf("не удалось удалить автозапуск старой версии PrivetDNS: %w", err)
		}
	}
	return archiveLegacyDirectory(dir)
}

func migrateLegacyInstallations(parent string) (int, error) {
	migrated := 0
	for _, item := range []struct {
		name    string
		migrate func(string) error
	}{
		{legacyNativeDirName, migrateLegacyNative},
		{legacyStubDirName, migrateLegacyStub},
	} {
		dir := filepath.Join(parent, item.name)
		if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return migrated, fmt.Errorf("не удалось проверить старую версию PrivetDNS: %w", err)
		}
		if err := item.migrate(dir); err != nil {
			return migrated, err
		}
		migrated++
	}
	return migrated, nil
}

func install(rawURL string) (string, error) {
	personalURL, err := validatePersonalURL(rawURL)
	if err != nil {
		return "", err
	}
	version := windows.RtlGetVersion()
	if version.MajorVersion < 10 || version.BuildNumber < 19041 {
		return "", errors.New("требуется Windows 10 версии 2004 или новее")
	}
	dir, stateFile, configFile, runtimeFile, domainsFile, err := paths()
	if err != nil {
		return "", err
	}
	serviceFound, err := servicePresent()
	if err != nil {
		return "", fmt.Errorf("не удалось проверить системную службу: %w", err)
	}
	if _, err := os.Lstat(dir); err == nil || !errors.Is(err, os.ErrNotExist) || taskExists() || serviceFound {
		return "", errors.New("PrivetDNS уже установлен или осталась старая установка; нажмите «Удалить», затем повторите")
	}
	if _, err := migrateLegacyInstallations(filepath.Dir(dir)); err != nil {
		return "", fmt.Errorf("не удалось перенести старую версию PrivetDNS: %w", err)
	}
	// NRPT entries can belong to local applications as well as domain policy.
	// They do not prohibit setting adapter DNS. Preserve them and rely on the
	// Windows DNS API to report an actual failure to apply the adapter setting.
	adapter, err := bestPhysicalAdapter()
	if err != nil {
		return "", err
	}
	original, err := snapshot(adapter)
	if err != nil {
		return "", err
	}
	ordinary := ordinaryResolvers(original.IPv4.Servers, original.IPv6.Servers)
	if len(ordinary) == 0 {
		return "", errors.New("у текущей сети не найден исходный DNS; переподключитесь к Wi-Fi или кабелю и повторите")
	}
	if _, err := parseNRPTDomains(domainsPayload); err != nil {
		return "", err
	}
	if err := protectDirectory(dir); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	installed := false
	serviceCreated := false
	dns4Changed := false
	dns6Changed := false
	defer func() {
		personalURL = ""
		if !installed {
			canRemoveFiles := !dns4Changed && !dns6Changed
			if serviceCreated && canRemoveFiles {
				canRemoveFiles = stopDeleteService() == nil
			}
			if canRemoveFiles {
				_ = os.RemoveAll(dir)
			}
		}
	}()
	serviceArguments := []string{"--service", "--config", configFile, "--port", "53"}
	if original.IPv6Enabled {
		serviceArguments = append(serviceArguments, "--ipv6")
	}
	state := savedState{Schema: 5, Adapter: original, ServiceCommand: runtimeFile, ServiceArguments: serviceArguments}
	stateData, _ := json.Marshal(state)
	configData, _ := json.Marshal(map[string]any{
		"doh_url": personalURL, "bootstrap_ips": []string{"31.76.244.138", "31.76.30.138"},
		"ordinary_dns": ordinary, "domains_file": domainsFile,
	})
	if err := writeExclusive(stateFile, stateData); err != nil {
		return "", err
	}
	if err := writeExclusive(configFile, configData); err != nil {
		return "", err
	}
	personalURL = ""
	if err := writeExclusive(runtimeFile, bridgePayload); err != nil {
		return "", err
	}
	if err := writeExclusive(domainsFile, domainsPayload); err != nil {
		return "", err
	}
	if err := createService(runtimeFile, serviceArguments); err != nil {
		return "", err
	}
	serviceCreated = true
	rollback := func(cause error) (string, error) {
		var restoreErr error
		if dns4Changed {
			if err := setDNSForAdapter(original, false, original.IPv4); err != nil {
				restoreErr = err
			} else {
				dns4Changed = false
			}
		}
		if dns6Changed {
			if err := setDNSForAdapter(original, true, original.IPv6); err != nil {
				restoreErr = err
			} else {
				dns6Changed = false
			}
		}
		if restoreErr != nil {
			return "", fmt.Errorf("%w; прежний DNS не удалось восстановить: %v. Файлы восстановления сохранены", cause, restoreErr)
		}
		return "", cause
	}
	if original.IPv6Enabled {
		dns6Changed = true
		if err := setLoopbackForAdapter(original, true); err != nil {
			return rollback(err)
		}
	}
	dns4Changed = true
	if err := setLoopbackForAdapter(original, false); err != nil {
		return rollback(err)
	}
	flushDNS()
	installed = true
	return "PrivetDNS установлен для подключения «" + original.Name + "».", nil
}

func uninstall() (string, error) {
	dir, stateFile, configFile, runtimeFile, _, err := paths()
	if err != nil {
		return "", err
	}
	if isReparse(dir) || isReparse(stateFile) {
		return "", errors.New("папка установки была подменена; автоматическое удаление остановлено")
	}
	data, err := os.ReadFile(stateFile)
	if err != nil || len(data) > 64*1024 {
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			return "", errors.New("сохранённая конфигурация PrivetDNS повреждена; автоматическое удаление остановлено")
		}
		recovered, recoverErr := recoverOrphanedInstall(dir, stateFile, configFile, runtimeFile)
		if recoverErr != nil {
			return "", recoverErr
		}
		if recovered {
			return "Остатки установки PrivetDNS убраны. Теперь можно установить заново.", nil
		}
		migrated, migrateErr := migrateLegacyInstallations(filepath.Dir(dir))
		if migrateErr != nil {
			return "", migrateErr
		}
		if migrated != 0 {
			return "Старая версия PrivetDNS удалена. Прежние настройки DNS восстановлены.", nil
		}
		return "", errors.New("сохранённая конфигурация PrivetDNS не найдена")
	}
	var state savedState
	if json.Unmarshal(data, &state) != nil {
		return "", errors.New("сохранённая конфигурация PrivetDNS повреждена")
	}
	if state.Schema == 1 {
		state, err = convertPowerShellState(data, runtimeFile, configFile)
		if err != nil {
			return "", err
		}
	}
	if !validAdapterGUID(state.Adapter.GUID) {
		return "", errors.New("сохранённая конфигурация PrivetDNS повреждена")
	}
	legacyTask := (state.Schema == 1 || state.Schema == 2) && strings.EqualFold(state.TaskCommand, runtimeFile)
	nrptService := state.Schema == 4 && strings.EqualFold(state.ServiceCommand, runtimeFile) && len(state.ServiceArguments) >= 5 && len(state.NRPTRules) != 0
	currentService := (state.Schema == 3 || state.Schema == 5 || nrptService) && strings.EqualFold(state.ServiceCommand, runtimeFile) && len(state.ServiceArguments) >= 5
	if !legacyTask && !currentService {
		return "", errors.New("сохранённая конфигурация PrivetDNS повреждена")
	}
	if legacyTask {
		if taskExists() {
			task, err := readTask()
			if err != nil || !strings.EqualFold(strings.TrimSpace(task.Actions.Exec.Command), state.TaskCommand) || strings.TrimSpace(task.Actions.Exec.Arguments) != state.TaskArguments || !strings.EqualFold(strings.TrimSpace(task.Principals.Principal.UserID), "S-1-5-18") {
				return "", errors.New("системная задача PrivetDNS была изменена; автоматическое удаление остановлено")
			}
		}
	} else {
		serviceFound, serviceErr := servicePresent()
		if serviceErr != nil {
			return "", fmt.Errorf("не удалось проверить службу PrivetDNS: %w", serviceErr)
		}
		if serviceFound {
			matches, matchErr := serviceMatches(state.ServiceCommand, state.ServiceArguments)
			if matchErr != nil || !matches {
				return "", errors.New("служба PrivetDNS была изменена; автоматическое удаление остановлено")
			}
		}
	}
	if nrptService {
		if err := validateInstalledNRPTRules(state.NRPTRules); err != nil {
			return "", err
		}
		if err := deleteNRPTRules(state.NRPTRules); err != nil {
			return "", err
		}
		if err := stopDeleteService(); err != nil {
			return "", fmt.Errorf("правила DNS удалены, но не удалось удалить службу: %w", err)
		}
		flushDNS()
		if err := os.RemoveAll(dir); err != nil {
			return "", fmt.Errorf("правила DNS удалены, но не удалось удалить файлы PrivetDNS: %w", err)
		}
		return "PrivetDNS удалён. DNS Wi-Fi и Ethernet не изменялся.", nil
	}
	info, err := adapterByGUID(state.Adapter.GUID)
	if err != nil {
		return "", err
	}
	state.Adapter.Name = info.Name
	state.Adapter.IfIndex = info.IfIndex
	current, err := snapshot(info)
	if err != nil {
		return "", err
	}
	// GetAdaptersAddresses is the authoritative live view. Registry-backed mode
	// detection can lag behind netsh on some Windows 11 network drivers.
	ours4 := isOnlyDNS(info.DNSv4, "127.0.0.1")
	ours6 := isOnlyDNS(info.DNSv6, "::1")
	if !ours4 && !sameFamily(current.IPv4, state.Adapter.IPv4) {
		return "", errors.New("IPv4 DNS изменён после установки; чтобы не потерять новые настройки, удаление остановлено")
	}
	if state.Adapter.IPv6Enabled && !ours6 && !sameFamily(current.IPv6, state.Adapter.IPv6) {
		return "", errors.New("IPv6 DNS изменён после установки; чтобы не потерять новые настройки, удаление остановлено")
	}
	if ours6 {
		if err := setDNSForAdapter(state.Adapter, true, state.Adapter.IPv6); err != nil {
			return "", fmt.Errorf("не удалось восстановить IPv6 DNS: %w", err)
		}
	}
	if ours4 {
		if err := setDNSForAdapter(state.Adapter, false, state.Adapter.IPv4); err != nil {
			return "", fmt.Errorf("не удалось восстановить IPv4 DNS: %w", err)
		}
	}
	if err := waitForRestoredDNS(state.Adapter); err != nil {
		return "", fmt.Errorf("проверка восстановленного DNS не пройдена; файлы восстановления сохранены: %w", err)
	}
	if currentService {
		if err := stopDeleteService(); err != nil {
			return "", fmt.Errorf("DNS восстановлен, но не удалось удалить службу: %w", err)
		}
	} else if taskExists() {
		_, _ = runHidden("schtasks.exe", "/End", "/TN", taskName)
		if _, err := runHidden("schtasks.exe", "/Delete", "/TN", taskName, "/F"); err != nil {
			return "", fmt.Errorf("DNS восстановлен, но не удалось удалить автозапуск: %w", err)
		}
	}
	flushDNS()
	if err := os.RemoveAll(dir); err != nil {
		return "", fmt.Errorf("DNS восстановлен, но не удалось удалить файлы PrivetDNS: %w", err)
	}
	return "PrivetDNS удалён. Прежние настройки DNS восстановлены.", nil
}

// Minimal native Win32 UI keeps the public installer independent of PowerShell,
// Python, .NET, WebView and third-party GUI runtimes.
type point struct{ X, Y int32 }
type message struct {
	Hwnd           windows.Handle
	Msg            uint32
	WParam, LParam uintptr
	Time           uint32
	Pt             point
}
type wndClassEx struct {
	Size                     uint32
	Style                    uint32
	WndProc                  uintptr
	ClsExtra, WndExtra       int32
	Instance                 windows.Handle
	Icon, Cursor, Background windows.Handle
	MenuName, ClassName      *uint16
	IconSmall                windows.Handle
}

var (
	user32                  = windows.NewLazySystemDLL("user32.dll")
	gdi32                   = windows.NewLazySystemDLL("gdi32.dll")
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procRegisterClassEx     = user32.NewProc("RegisterClassExW")
	procCreateWindowEx      = user32.NewProc("CreateWindowExW")
	procDefWindowProc       = user32.NewProc("DefWindowProcW")
	procShowWindow          = user32.NewProc("ShowWindow")
	procUpdateWindow        = user32.NewProc("UpdateWindow")
	procGetMessage          = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessage     = user32.NewProc("DispatchMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procSendMessage         = user32.NewProc("SendMessageW")
	procPostMessage         = user32.NewProc("PostMessageW")
	procSetWindowText       = user32.NewProc("SetWindowTextW")
	procGetWindowText       = user32.NewProc("GetWindowTextW")
	procGetWindowTextLength = user32.NewProc("GetWindowTextLengthW")
	procEnableWindow        = user32.NewProc("EnableWindow")
	procMessageBox          = user32.NewProc("MessageBoxW")
	procDestroyWindow       = user32.NewProc("DestroyWindow")
	procGetSystemMetrics    = user32.NewProc("GetSystemMetrics")
	procLoadCursor          = user32.NewProc("LoadCursorW")
	procGetStockObject      = gdi32.NewProc("GetStockObject")
	procGetModuleHandle     = kernel32.NewProc("GetModuleHandleW")
)

const (
	wsOverlappedWindow = 0x00CF0000
	wsChild            = 0x40000000
	wsVisible          = 0x10000000
	wsBorder           = 0x00800000
	wsTabStop          = 0x00010000
	esAutoHScroll      = 0x0080
	esPassword         = 0x0020
	bsPushButton       = 0x00000000
	bsAutoCheckbox     = 0x00000003
	wmCreate           = 0x0001
	wmDestroy          = 0x0002
	wmClose            = 0x0010
	wmCommand          = 0x0111
	wmSetFont          = 0x0030
	emSetPasswordChar  = 0x00CC
	bmGetCheck         = 0x00F0
	wmAppDone          = 0x8001
	wmAppAutoRemove    = 0x8002
	swShow             = 5
	mbOK               = 0
	mbIconError        = 0x10
	mbIconInformation  = 0x40
	idEdit             = 1001
	idShow             = 1002
	idInstall          = 1003
	idRemove           = 1004
)

var (
	mainWindow, editControl, showControl, installButton, removeButton, statusControl windows.Handle
	uiBusy                                                                           bool
	resultMu                                                                         sync.Mutex
	resultText                                                                       string
	resultErr                                                                        error
	autoRemove                                                                       bool
)

func utf16(value string) *uint16 { return windows.StringToUTF16Ptr(value) }

func createControl(class, text string, style uint32, x, y, width, height int32, parent windows.Handle, id int) windows.Handle {
	handle, _, _ := procCreateWindowEx.Call(0, uintptr(unsafe.Pointer(utf16(class))), uintptr(unsafe.Pointer(utf16(text))), uintptr(style),
		uintptr(x), uintptr(y), uintptr(width), uintptr(height), uintptr(parent), uintptr(id), 0, 0)
	font, _, _ := procGetStockObject.Call(17)
	procSendMessage.Call(handle, wmSetFont, font, 1)
	return windows.Handle(handle)
}

func setText(handle windows.Handle, value string) {
	procSetWindowText.Call(uintptr(handle), uintptr(unsafe.Pointer(utf16(value))))
}

func getText(handle windows.Handle) string {
	length, _, _ := procGetWindowTextLength.Call(uintptr(handle))
	buffer := make([]uint16, length+1)
	procGetWindowText.Call(uintptr(handle), uintptr(unsafe.Pointer(&buffer[0])), length+1)
	return windows.UTF16ToString(buffer)
}

func enableControls(enabled bool) {
	value := uintptr(0)
	if enabled {
		value = 1
	}
	procEnableWindow.Call(uintptr(editControl), value)
	procEnableWindow.Call(uintptr(installButton), value)
	procEnableWindow.Call(uintptr(removeButton), value)
}

func beginOperation(remove bool) {
	if uiBusy {
		return
	}
	uiBusy = true
	enableControls(false)
	setText(statusControl, "Установка DNS…")
	raw := ""
	if !remove {
		raw = getText(editControl)
		setText(editControl, "")
	}
	go func() {
		var text string
		var err error
		if remove {
			text, err = uninstall()
		} else {
			text, err = install(raw)
		}
		raw = ""
		resultMu.Lock()
		resultText, resultErr = text, err
		resultMu.Unlock()
		procPostMessage.Call(uintptr(mainWindow), wmAppDone, 0, 0)
	}()
}

func windowProc(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmCreate:
		createControl("STATIC", "PrivetDNS для Windows · версия "+setupVersion, wsChild|wsVisible, 24, 18, 490, 28, hwnd, 0)
		createControl("STATIC", "Вставьте персональную DoH-ссылку из карточки устройства.", wsChild|wsVisible, 24, 52, 490, 52, hwnd, 0)
		editControl = createControl("EDIT", "", wsChild|wsVisible|wsBorder|wsTabStop|esAutoHScroll|esPassword, 24, 112, 490, 28, hwnd, idEdit)
		showControl = createControl("BUTTON", "Показать ссылку", wsChild|wsVisible|wsTabStop|bsAutoCheckbox, 24, 146, 180, 24, hwnd, idShow)
		installButton = createControl("BUTTON", "Установить", wsChild|wsVisible|wsTabStop|bsPushButton, 24, 184, 150, 38, hwnd, idInstall)
		removeButton = createControl("BUTTON", "Удалить PrivetDNS", wsChild|wsVisible|wsTabStop|bsPushButton, 188, 184, 210, 38, hwnd, idRemove)
		statusControl = createControl("STATIC", "Готово к установке.", wsChild|wsVisible, 24, 236, 490, 44, hwnd, 0)
		if autoRemove {
			procPostMessage.Call(uintptr(hwnd), wmAppAutoRemove, 0, 0)
		}
		return 0
	case wmCommand:
		switch int(wParam & 0xffff) {
		case idShow:
			checked, _, _ := procSendMessage.Call(uintptr(showControl), bmGetCheck, 0, 0)
			character := uintptr('*')
			if checked != 0 {
				character = 0
			}
			procSendMessage.Call(uintptr(editControl), emSetPasswordChar, character, 0)
			setText(editControl, getText(editControl))
		case idInstall:
			beginOperation(false)
		case idRemove:
			beginOperation(true)
		}
		return 0
	case wmAppAutoRemove:
		beginOperation(true)
		return 0
	case wmAppDone:
		resultMu.Lock()
		text, err := resultText, resultErr
		resultMu.Unlock()
		uiBusy = false
		enableControls(true)
		if err != nil {
			setText(statusControl, "Установка не завершена.")
			procMessageBox.Call(uintptr(hwnd), uintptr(unsafe.Pointer(utf16(err.Error()))), uintptr(unsafe.Pointer(utf16("PrivetDNS — ошибка"))), mbOK|mbIconError)
		} else {
			setText(statusControl, text)
			procMessageBox.Call(uintptr(hwnd), uintptr(unsafe.Pointer(utf16(text))), uintptr(unsafe.Pointer(utf16("PrivetDNS"))), mbOK|mbIconInformation)
		}
		return 0
	case wmClose:
		if uiBusy {
			procMessageBox.Call(uintptr(hwnd), uintptr(unsafe.Pointer(utf16("Дождитесь завершения операции."))), uintptr(unsafe.Pointer(utf16("PrivetDNS"))), mbOK|mbIconInformation)
			return 0
		}
		procDestroyWindow.Call(uintptr(hwnd))
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	value, _, _ := procDefWindowProc.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return value
}

func quoteCommandLine(args []string) string {
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "" || strings.ContainsAny(arg, " \t\"") {
			arg = `"` + strings.ReplaceAll(arg, `"`, `\"`) + `"`
		}
		parts = append(parts, arg)
	}
	return strings.Join(parts, " ")
}

func elevateIfNeeded() (bool, error) {
	if windows.GetCurrentProcessToken().IsElevated() {
		return false, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return false, err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(executable)
	args, _ := windows.UTF16PtrFromString(quoteCommandLine(os.Args[1:]))
	if err := windows.ShellExecute(0, verb, file, args, nil, swShow); err != nil {
		return false, err
	}
	return true, nil
}

func runUI() error {
	instance, _, _ := procGetModuleHandle.Call(0)
	className := utf16("PrivetDNSSetupWindow")
	cursor, _, _ := procLoadCursor.Call(0, 32512)
	callback := syscall.NewCallback(windowProc)
	class := wndClassEx{Size: uint32(unsafe.Sizeof(wndClassEx{})), WndProc: callback, Instance: windows.Handle(instance), Cursor: windows.Handle(cursor), Background: windows.Handle(6), ClassName: className}
	registered, _, registerErr := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&class)))
	if registered == 0 {
		return registerErr
	}
	width, height := int32(560), int32(340)
	screenW, _, _ := procGetSystemMetrics.Call(0)
	screenH, _, _ := procGetSystemMetrics.Call(1)
	x, y := (int32(screenW)-width)/2, (int32(screenH)-height)/2
	hwnd, _, createErr := procCreateWindowEx.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(utf16("PrivetDNS — установка"))), wsOverlappedWindow,
		uintptr(x), uintptr(y), uintptr(width), uintptr(height), 0, 0, instance, 0)
	if hwnd == 0 {
		return createErr
	}
	mainWindow = windows.Handle(hwnd)
	procShowWindow.Call(hwnd, swShow)
	procUpdateWindow.Call(hwnd)
	var msg message
	for {
		result, _, err := procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(result) == -1 {
			return err
		}
		if result == 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
	runtime.KeepAlive(callback)
	return nil
}

func main() {
	runtime.LockOSThread()
	for _, arg := range os.Args[1:] {
		if arg == "--uninstall" {
			autoRemove = true
		}
	}
	relaunched, err := elevateIfNeeded()
	if relaunched {
		return
	}
	if err != nil {
		procMessageBox.Call(0, uintptr(unsafe.Pointer(utf16("Не удалось запросить права администратора: "+err.Error()))), uintptr(unsafe.Pointer(utf16("PrivetDNS"))), mbOK|mbIconError)
		return
	}
	if err := runUI(); err != nil {
		procMessageBox.Call(0, uintptr(unsafe.Pointer(utf16("Не удалось открыть установщик: "+err.Error()))), uintptr(unsafe.Pointer(utf16("PrivetDNS"))), mbOK|mbIconError)
	}
}
