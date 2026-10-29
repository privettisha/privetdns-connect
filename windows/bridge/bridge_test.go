package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func testQuery() []byte {
	return []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'o', 'r', 'g', 0, 0, 1, 0, 1}
}

func TestPersonalURL(t *testing.T) {
	good := "https://dns.privetdns.ru/dns-query/device/" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := validURL(good); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"?dns=abc", "../", "/extra", "!"} {
		if _, err := validURL(good + suffix); err == nil {
			t.Errorf("accepted invalid URL suffix %q", suffix)
		}
	}
}

func TestDoHReplyAndTruncation(t *testing.T) {
	query := testQuery()
	answer := append([]byte(nil), query...)
	answer[2] = 0x81
	answer[3] = 0x80
	answer = append(answer, bytes.Repeat([]byte{0}, 600)...)
	b := &bridge{endpoint: "https://dns.privetdns.ru/dns-query/device/test", domains: map[string]struct{}{"example.org": {}}, slots: make(chan struct{}, 1)}
	b.clients = []*http.Client{{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/dns-message" || !bytes.Equal(body, query) {
			t.Error("incorrect DoH request")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/dns-message"}}, Body: io.NopCloser(bytes.NewReader(answer))}, nil
	})}}
	got, err := b.resolve(query, false)
	if err != nil || !bytes.Equal(got, answer) {
		t.Fatalf("DoH response failed: %v", err)
	}
	truncated := truncatedReply(query, got)
	if len(truncated) >= 512 || binary.BigEndian.Uint16(truncated[2:4])&0x0200 == 0 || binary.BigEndian.Uint16(truncated[6:8]) != 0 {
		t.Fatal("invalid truncated UDP response")
	}
}

func TestRejectMismatchedResponse(t *testing.T) {
	query := testQuery()
	answer := append([]byte(nil), query...)
	answer[2] = 0x81
	answer[13] = 'x'
	b := &bridge{endpoint: "https://dns.privetdns.ru/dns-query/device/test", domains: map[string]struct{}{"example.org": {}}, clients: []*http.Client{{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/dns-message"}}, Body: io.NopCloser(bytes.NewReader(answer))}, nil
	})}}}
	if _, err := b.resolve(query, false); err == nil {
		t.Fatal("mismatched DNS question accepted")
	}
}

func TestSuffixPolicy(t *testing.T) {
	domains := map[string]struct{}{"gemini.google.com": {}, "openai.com": {}}
	for _, name := range []string{"gemini.google.com", "a.gemini.google.com", "api.openai.com"} {
		if !matches(name, domains) {
			t.Errorf("expected match for %s", name)
		}
	}
	for _, name := range []string{"google.com", "badgemini.google.com", "openai.com.evil"} {
		if matches(name, domains) {
			t.Errorf("unexpected match for %s", name)
		}
	}
}

func TestUnmatchedNameNeverUsesPersonalDoH(t *testing.T) {
	called := false
	b := &bridge{endpoint: "https://dns.privetdns.ru/dns-query/device/test",
		domains: map[string]struct{}{"gemini.google.com": {}}, ordinaryDNS: []string{"127.0.0.2"},
		clients: []*http.Client{{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("must not be called")
		})}}}
	if _, err := b.resolve(testQuery(), false); err == nil {
		t.Fatal("unreachable ordinary test resolver unexpectedly answered")
	}
	if called {
		t.Fatal("ordinary domain leaked to personal DoH")
	}
}

func TestServfailKeepsQuestion(t *testing.T) {
	query := testQuery()
	reply := servfail(query)
	if len(reply) != len(query) || reply[3]&15 != 2 || !bytes.Equal(reply[12:], query[12:]) {
		t.Fatal("invalid SERVFAIL response")
	}
}
