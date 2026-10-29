package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalUIRequiresSession(t *testing.T) {
	app := &application{token: strings.Repeat("a", 48)}
	handler := app.handler()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:12345/api/status", nil)
	request.Host = "127.0.0.1:12345"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unauthorized status: %d", response.Code)
	}
	request.Header.Set("X-PrivetDNS-Session", app.token)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authorized status: %d", response.Code)
	}
}

func TestInstallRejectsWrongHostBeforeRunningInstaller(t *testing.T) {
	app := &application{token: strings.Repeat("a", 48)}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:12345/api/install",
		strings.NewReader(`{"host":"https://dns.privetdns.ru/dns-query/device/secret"}`))
	request.Host = "127.0.0.1:12345"
	request.Header.Set("Origin", "http://127.0.0.1:12345")
	request.Header.Set("X-PrivetDNS-Session", app.token)
	response := httptest.NewRecorder()
	app.handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid host status: %d", response.Code)
	}
}
