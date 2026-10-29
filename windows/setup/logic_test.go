package main

import "testing"

func TestValidatePersonalURL(t *testing.T) {
	good := "https://dns.privetdns.ru/dns-query/device/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno"
	if got, err := validatePersonalURL(good); err != nil || got != good {
		t.Fatalf("valid URL rejected: %q %v", got, err)
	}
	bad := []string{
		"http://dns.privetdns.ru/dns-query/device/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno",
		"https://evil.example/dns-query/device/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno",
		good + "?x=1", good + " ", "https://dns.privetdns.ru/dns-query/device/short",
	}
	for _, value := range bad {
		if _, err := validatePersonalURL(value); err == nil {
			t.Fatalf("invalid URL accepted: %q", value)
		}
	}
}

func TestNormalizeServers(t *testing.T) {
	got := normalizeServers([]string{"192.168.1.1", "192.168.1.1", "::1", "fe80::1", "8.8.8.8"}, 4)
	if len(got) != 2 || got[0] != "192.168.1.1" || got[1] != "8.8.8.8" {
		t.Fatalf("unexpected servers: %#v", got)
	}
	observed := normalizeAdapterServers([]string{"127.0.0.1", "::1"}, 4)
	if len(observed) != 1 || observed[0] != "127.0.0.1" {
		t.Fatalf("live loopback DNS was discarded: %#v", observed)
	}
}

func TestOrdinaryResolversKeepNetworkFirstAndAddFallback(t *testing.T) {
	got := ordinaryResolvers([]string{"192.168.1.1", "1.1.1.1"}, []string{"fe80::1"})
	want := []string{"192.168.1.1", "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"}
	if len(got) != len(want) {
		t.Fatalf("unexpected resolver count: %#v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("unexpected resolver order: %#v", got)
		}
	}
}

func TestFamilyComparison(t *testing.T) {
	autoA := dnsFamilyState{Mode: "automatic", Servers: []string{"192.168.1.1"}}
	autoB := dnsFamilyState{Mode: "automatic", Servers: []string{"10.0.0.1"}}
	if !sameFamily(autoA, autoB) {
		t.Fatal("automatic DNS should compare by mode")
	}
	static := dnsFamilyState{Mode: "static", Servers: []string{"127.0.0.1"}}
	if !isOurLoopback(static, "127.0.0.1") || sameFamily(static, autoA) {
		t.Fatal("static DNS comparison failed")
	}
	if !isOnlyDNS([]string{"127.0.0.1"}, "127.0.0.1") || isOnlyDNS([]string{"127.0.0.1", "8.8.8.8"}, "127.0.0.1") {
		t.Fatal("live DNS comparison failed")
	}
}

func TestDNSInstallVerificationAcceptsWorkingWindowsResolverWithStaleAdapterList(t *testing.T) {
	if loopbackDNSApplied([]string{"192.168.1.1"}, []string{"2001:db8::1"}, true) {
		t.Fatal("stale adapter list must not look applied")
	}
	if !dnsInstallVerified(false, true) {
		t.Fatal("a verified Windows system lookup must prevent a false rollback")
	}
	if dnsInstallVerified(false, false) {
		t.Fatal("installation must fail when neither verification path succeeds")
	}
}

func TestDecodeCommandOutput(t *testing.T) {
	input := []byte{0xff, 0xfe, '<', 0, 'T', 0, 'a', 0, 's', 0, 'k', 0, '>', 0}
	if got := decodeCommandOutput(input); got != "<Task>" {
		t.Fatalf("unexpected UTF-16 output: %q", got)
	}
	if got := decodeCommandOutput([]byte("plain")); got != "plain" {
		t.Fatalf("unexpected plain output: %q", got)
	}
	if got := decodeCommandOutput([]byte{0x8e, 0xe8, 0xa8, 0xa1, 0xaa, 0xa0}); got != "" {
		t.Fatalf("invalid OEM output must not be shown as mojibake: %q", got)
	}
}

func TestParseNRPTDomainsAndStableRuleNames(t *testing.T) {
	domains, err := parseNRPTDomains([]byte("# comment\nGemini.Google.Com\r\nchatgpt.com\n"))
	if err != nil || len(domains) != 2 || domains[0] != "gemini.google.com" {
		t.Fatalf("unexpected domains: %#v %v", domains, err)
	}
	name := nrptRuleName(domains[0])
	if !validNRPTRuleName(name) || name != nrptRuleName("gemini.google.com") {
		t.Fatalf("invalid stable rule name: %q", name)
	}
	for _, input := range []string{"", "example", "bad_name.example", "a..example.com", "example.com\nexample.com"} {
		if _, err := parseNRPTDomains([]byte(input)); err == nil {
			t.Fatalf("invalid domain payload accepted: %q", input)
		}
	}
	if validNRPTRuleName(`PrivetDNS-../../DnsPolicyConfig`) {
		t.Fatal("unsafe registry rule name accepted")
	}
}
