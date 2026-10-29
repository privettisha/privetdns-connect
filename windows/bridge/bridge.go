package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const maxDNS = 4096
const windowsServiceName = "PrivetDNSWindowsBridge"

var personalPath = regexp.MustCompile(`^/dns-query/device/[A-Za-z0-9_-]{40,64}$`)

type config struct {
	DoHURL       string   `json:"doh_url"`
	BootstrapIPs []string `json:"bootstrap_ips"`
	OrdinaryDNS  []string `json:"ordinary_dns"`
	DomainsFile  string   `json:"domains_file"`
}

type bridge struct {
	endpoint    string
	clients     []*http.Client
	ordinaryDNS []string
	domains     map[string]struct{}
	slots       chan struct{}
}

func validURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "https" || u.Hostname() != "dns.privetdns.ru" || u.Port() != "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(raw, " \t\r\n") {
		return nil, errors.New("invalid PrivetDNS HTTPS URL")
	}
	if !personalPath.MatchString(u.EscapedPath()) || u.RawQuery != "" {
		return nil, errors.New("invalid personal DoH path")
	}
	return u, nil
}

func validIPList(values []string, field string) ([]string, error) {
	if len(values) == 0 || len(values) > 8 {
		return nil, fmt.Errorf("invalid %s", field)
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		ip := net.ParseIP(value)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, fmt.Errorf("invalid %s", field)
		}
		normalized := ip.String()
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}
	return result, nil
}

func loadDomains(path string) (map[string]struct{}, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("domain policy unavailable")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > 128*1024 {
		return nil, errors.New("invalid domain policy")
	}
	result := make(map[string]struct{})
	for _, raw := range strings.Split(string(data), "\n") {
		name := strings.TrimSpace(raw)
		if name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		if name != strings.ToLower(name) || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || len(name) > 253 {
			return nil, errors.New("invalid domain policy entry")
		}
		for _, label := range strings.Split(name, ".") {
			if label == "" || len(label) > 63 {
				return nil, errors.New("invalid domain policy entry")
			}
			for i, char := range label {
				if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || (char == '-' && i > 0 && i < len(label)-1)) {
					return nil, errors.New("invalid domain policy entry")
				}
			}
		}
		if _, exists := result[name]; exists {
			return nil, errors.New("duplicate domain policy entry")
		}
		result[name] = struct{}{}
	}
	if len(result) == 0 {
		return nil, errors.New("empty domain policy")
	}
	return result, nil
}

func dohClient(ip, hostname string) *http.Client {
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostname},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
		},
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     30 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 7 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func newBridge(cfg config) (*bridge, error) {
	u, err := validURL(cfg.DoHURL)
	if err != nil {
		return nil, err
	}
	bootstrap, err := validIPList(cfg.BootstrapIPs, "bootstrap addresses")
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{"31.76.244.138": true, "31.76.30.138": true}
	for _, ip := range bootstrap {
		if !allowed[ip] {
			return nil, errors.New("invalid bootstrap address")
		}
	}
	ordinary, err := validIPList(cfg.OrdinaryDNS, "ordinary DNS addresses")
	if err != nil {
		return nil, err
	}
	domains, err := loadDomains(cfg.DomainsFile)
	if err != nil {
		return nil, err
	}
	clients := make([]*http.Client, 0, len(bootstrap))
	for _, ip := range bootstrap {
		clients = append(clients, dohClient(ip, u.Hostname()))
	}
	return &bridge{endpoint: u.String(), clients: clients, ordinaryDNS: ordinary,
		domains: domains, slots: make(chan struct{}, 64)}, nil
}

func question(packet []byte) (int, string, error) {
	if len(packet) < 17 || binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return 0, "", errors.New("invalid DNS question")
	}
	i := 12
	labels := make([]string, 0, 8)
	for labelCount := 0; labelCount < 128; labelCount++ {
		if i >= len(packet) {
			return 0, "", errors.New("truncated DNS name")
		}
		n := int(packet[i])
		i++
		if n == 0 {
			if i+4 > len(packet) {
				return 0, "", errors.New("truncated DNS type")
			}
			if len(labels) == 0 {
				return 0, "", errors.New("empty DNS name")
			}
			return i + 4, strings.ToLower(strings.Join(labels, ".")), nil
		}
		if n > 63 || i+n > len(packet) {
			return 0, "", errors.New("invalid DNS label")
		}
		label := packet[i : i+n]
		for _, char := range label {
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
				return 0, "", errors.New("invalid DNS label")
			}
		}
		labels = append(labels, string(label))
		i += n
	}
	return 0, "", errors.New("DNS name too long")
}

func questionEnd(packet []byte) (int, error) {
	end, _, err := question(packet)
	return end, err
}

func matches(name string, domains map[string]struct{}) bool {
	for {
		if _, ok := domains[name]; ok {
			return true
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			return false
		}
		name = name[dot+1:]
	}
}

func truncatedReply(query, answer []byte) []byte {
	end, err := questionEnd(query)
	if err != nil {
		return nil
	}
	result := make([]byte, end)
	copy(result, query[:end])
	flags := uint16(0x8200) | (binary.BigEndian.Uint16(query[2:4]) & 0x7900) | (binary.BigEndian.Uint16(answer[2:4]) & 0x008f)
	binary.BigEndian.PutUint16(result[2:4], flags)
	binary.BigEndian.PutUint16(result[6:8], 0)
	binary.BigEndian.PutUint16(result[8:10], 0)
	binary.BigEndian.PutUint16(result[10:12], 0)
	return result
}

func (b *bridge) doh(query []byte) ([]byte, error) {
	var last error
	for _, client := range b.clients {
		answer, err := b.dohWithClient(query, client)
		if err == nil {
			return answer, nil
		}
		last = err
	}
	return nil, last
}

func (b *bridge) dohWithClient(query []byte, client *http.Client) ([]byte, error) {
	if len(query) > maxDNS || len(query) < 17 || query[2]&0x80 != 0 {
		return nil, errors.New("invalid DNS query")
	}
	end, err := questionEnd(query)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.EqualFold(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]), "application/dns-message") {
		return nil, errors.New("invalid DoH response")
	}
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil || len(answer) < 17 || len(answer) > 65535 || !bytes.Equal(answer[:2], query[:2]) || answer[2]&0x80 == 0 {
		return nil, errors.New("invalid DNS reply")
	}
	answerEnd, err := questionEnd(answer)
	if err != nil || !bytes.Equal(bytes.ToLower(answer[12:answerEnd]), bytes.ToLower(query[12:end])) {
		return nil, errors.New("mismatched DNS question")
	}
	return answer, nil
}

func validReply(query, answer []byte) error {
	queryEnd, err := questionEnd(query)
	if err != nil || len(answer) < 17 || len(answer) > 65535 || !bytes.Equal(answer[:2], query[:2]) || answer[2]&0x80 == 0 {
		return errors.New("invalid DNS reply")
	}
	answerEnd, err := questionEnd(answer)
	if err != nil || !bytes.Equal(bytes.ToLower(answer[12:answerEnd]), bytes.ToLower(query[12:queryEnd])) {
		return errors.New("mismatched DNS question")
	}
	return nil
}

func directTCP(query []byte, address string) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, "53"), 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	header := []byte{byte(len(query) >> 8), byte(len(query))}
	if _, err = conn.Write(append(header, query...)); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header))
	if size < 17 || size > 65535 {
		return nil, errors.New("invalid ordinary DNS reply")
	}
	answer := make([]byte, size)
	if _, err = io.ReadFull(conn, answer); err != nil {
		return nil, err
	}
	return answer, validReply(query, answer)
}

func directUDP(query []byte, address string) ([]byte, error) {
	peer, err := net.ResolveUDPAddr("udp", net.JoinHostPort(address, "53"))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, peer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write(query); err != nil {
		return nil, err
	}
	answer := make([]byte, 65536)
	n, err := conn.Read(answer)
	if err != nil {
		return nil, err
	}
	answer = answer[:n]
	if err = validReply(query, answer); err != nil {
		return nil, err
	}
	if answer[2]&0x02 != 0 {
		return directTCP(query, address)
	}
	return answer, nil
}

func (b *bridge) ordinary(query []byte, tcp bool) ([]byte, error) {
	var last error
	for _, address := range b.ordinaryDNS {
		var answer []byte
		var err error
		if tcp {
			answer, err = directTCP(query, address)
		} else {
			answer, err = directUDP(query, address)
		}
		if err == nil {
			return answer, nil
		}
		last = err
	}
	return nil, last
}

func servfail(query []byte) []byte {
	end, err := questionEnd(query)
	if err != nil {
		return nil
	}
	result := append([]byte(nil), query[:end]...)
	binary.BigEndian.PutUint16(result[2:4], 0x8002|(binary.BigEndian.Uint16(query[2:4])&0x0100))
	binary.BigEndian.PutUint16(result[6:8], 0)
	binary.BigEndian.PutUint16(result[8:10], 0)
	binary.BigEndian.PutUint16(result[10:12], 0)
	return result
}

func (b *bridge) resolve(query []byte, tcp bool) ([]byte, error) {
	_, name, err := question(query)
	if err != nil || len(query) > maxDNS || query[2]&0x80 != 0 {
		return nil, errors.New("invalid DNS query")
	}
	if matches(name, b.domains) {
		return b.doh(query)
	}
	return b.ordinary(query, tcp)
}

func (b *bridge) serveUDP(addr string) (net.PacketConn, error) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		buffer := make([]byte, maxDNS+1)
		for {
			n, peer, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			select {
			case b.slots <- struct{}{}:
			default:
				continue
			}
			query := append([]byte(nil), buffer[:n]...)
			go func() {
				defer func() { <-b.slots }()
				answer, err := b.resolve(query, false)
				if err != nil {
					answer = servfail(query)
				}
				if len(answer) > 512 {
					answer = truncatedReply(query, answer)
				}
				if len(answer) != 0 {
					_, _ = conn.WriteTo(answer, peer)
				}
			}()
		}
	}()
	return conn, nil
}

func (b *bridge) serveTCP(addr string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case b.slots <- struct{}{}:
			default:
				_ = conn.Close()
				continue
			}
			go func() {
				defer func() { <-b.slots }()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
				header := make([]byte, 2)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(header))
				if n < 17 || n > maxDNS {
					return
				}
				query := make([]byte, n)
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				answer, err := b.resolve(query, true)
				if err != nil {
					answer = servfail(query)
				}
				if len(answer) == 0 {
					return
				}
				binary.BigEndian.PutUint16(header, uint16(len(answer)))
				_, _ = conn.Write(append(header, answer...))
			}()
		}
	}()
	return listener, nil
}

type bridgeRuntime struct {
	packets   []net.PacketConn
	listeners []net.Listener
}

func (r *bridgeRuntime) Close() {
	for _, packet := range r.packets {
		_ = packet.Close()
	}
	for _, listener := range r.listeners {
		_ = listener.Close()
	}
}

func startConfiguredBridge(path string, port int, ipv6 bool) (*bridgeRuntime, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("configuration unavailable")
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, errors.New("invalid configuration")
	}
	b, err := newBridge(cfg)
	if err != nil {
		return nil, errors.New("invalid configuration")
	}
	addresses := []string{fmt.Sprintf("127.0.0.1:%d", port)}
	if ipv6 {
		addresses = append(addresses, fmt.Sprintf("[::1]:%d", port))
	}
	runtime := &bridgeRuntime{}
	for _, addr := range addresses {
		packet, err := b.serveUDP(addr)
		if err != nil {
			runtime.Close()
			return nil, fmt.Errorf("local UDP port unavailable: %w", err)
		}
		runtime.packets = append(runtime.packets, packet)
		listener, err := b.serveTCP(addr)
		if err != nil {
			runtime.Close()
			return nil, fmt.Errorf("local TCP port unavailable: %w", err)
		}
		runtime.listeners = append(runtime.listeners, listener)
	}
	return runtime, nil
}

func main() {
	path := flag.String("config", "", "private configuration path")
	port := flag.Int("port", 53, "loopback DNS port")
	ipv6 := flag.Bool("ipv6", false, "also listen on IPv6 loopback")
	serviceMode := flag.Bool("service", false, "run as a Windows service")
	flag.Parse()
	if *path == "" || *port < 1 || *port > 65535 {
		log.Fatal("config and valid port required")
	}
	start := func() (*bridgeRuntime, error) {
		return startConfiguredBridge(*path, *port, *ipv6)
	}
	if *serviceMode {
		if err := runWindowsService(windowsServiceName, start); err != nil {
			log.Print("Windows service failed: ", err)
			os.Exit(1)
		}
		return
	}
	runtime, err := start()
	if err != nil {
		log.Fatal(err)
	}
	defer runtime.Close()
	log.Print("PrivetDNS local DNS bridge ready")
	select {}
}
