package main

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed ui/index.html ui/app.css ui/app.js install.py splitdns.py smartdns-domains.txt
var files embed.FS

var dotHost = regexp.MustCompile(`^[a-z2-7]{32}\.dot\.privetdns\.ru$`)

type application struct {
	token string
	work  string
	mu    sync.Mutex
}

func temporaryScripts() (string, error) {
	dir, err := os.MkdirTemp("/var/lib", "privetdns-connect-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return "", err
	}
	for _, name := range []string{"install.py", "splitdns.py", "smartdns-domains.txt"} {
		data, err := files.ReadFile(name)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func (a *application) authorized(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-PrivetDNS-Session") != a.token || !strings.HasPrefix(r.Host, "127.0.0.1:") {
		http.Error(w, "Доступ закрыт", http.StatusForbidden)
		return false
	}
	if r.Method == http.MethodPost && r.Header.Get("Origin") != "http://"+r.Host {
		http.Error(w, "Доступ закрыт", http.StatusForbidden)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func installedStatus() map[string]any {
	state, err := os.ReadFile("/var/lib/privetdns-native/state.json")
	if err != nil {
		return map[string]any{"installed": false, "healthy": false}
	}
	var saved struct {
		Restored bool `json:"restored"`
	}
	if json.Unmarshal(state, &saved) != nil || saved.Restored {
		return map[string]any{"installed": false, "healthy": false}
	}
	cmd := exec.Command("/usr/bin/systemctl", "is-active", "privetdns-splitdns.service")
	return map[string]any{"installed": true, "healthy": cmd.Run() == nil}
}

func (a *application) operation(action, host string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	args := []string{filepath.Join(a.work, "install.py"), action}
	if action == "install" {
		args = append(args, "--host-stdin")
	}
	cmd := exec.Command("/usr/bin/python3", args...)
	cmd.Dir = a.work
	cmd.Stdin = strings.NewReader(host + "\n")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	message := strings.TrimSpace(strings.ReplaceAll(output.String(), host, "[скрыто]"))
	if len(message) > 2000 {
		message = message[len(message)-2000:]
	}
	if err != nil {
		if message == "" {
			message = err.Error()
		}
		return "", errors.New(message)
	}
	return message, nil
}

func (a *application) handler() http.Handler {
	mux := http.NewServeMux()
	for _, asset := range []struct{ path, name, kind string }{
		{"/", "ui/index.html", "text/html; charset=utf-8"},
		{"/app.css", "ui/app.css", "text/css; charset=utf-8"},
		{"/app.js", "ui/app.js", "application/javascript; charset=utf-8"},
	} {
		asset := asset
		mux.HandleFunc(asset.path, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != asset.path || r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			data, err := files.ReadFile(asset.name)
			if err != nil {
				http.Error(w, "Файл интерфейса недоступен", 500)
				return
			}
			w.Header().Set("Content-Type", asset.kind)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			_, _ = w.Write(data)
		})
	}
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if !a.authorized(w, r) || r.Method != http.MethodGet {
			return
		}
		writeJSON(w, 200, installedStatus())
	})
	mux.HandleFunc("/api/install", func(w http.ResponseWriter, r *http.Request) {
		if !a.authorized(w, r) || r.Method != http.MethodPost {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 512)
		var request struct {
			Host string `json:"host"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || !dotHost.MatchString(request.Host) {
			writeJSON(w, 400, map[string]string{"error": "Вставьте личное имя DoT из карточки Linux-устройства"})
			return
		}
		message, err := a.operation("install", request.Host)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"message": message})
	})
	mux.HandleFunc("/api/remove", func(w http.ResponseWriter, r *http.Request) {
		if !a.authorized(w, r) || r.Method != http.MethodPost {
			return
		}
		message, err := a.operation("remove", "")
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"message": message})
	})
	return mux
}

func openBrowser(address string) {
	username := os.Getenv("SUDO_USER")
	if username == "" || username == "root" || strings.ContainsAny(username, "/:\n") {
		return
	}
	args := []string{"-u", username, "--", "/usr/bin/env"}
	for _, key := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if value := os.Getenv(key); value != "" {
			args = append(args, key+"="+value)
		}
	}
	args = append(args, "xdg-open", address)
	_ = exec.Command("/usr/bin/runuser", args...).Start()
}

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Запустите: sudo ./PrivetDNS-Connect")
		os.Exit(1)
	}
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	work, err := temporaryScripts()
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(work)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	app := &application{token: hex.EncodeToString(secret), work: work}
	server := &http.Server{Handler: app.handler(), ReadHeaderTimeout: 5 * time.Second}
	address := "http://" + listener.Addr().String() + "/#" + app.token
	fmt.Println("PrivetDNS Connect открыт:", address)
	fmt.Println("Оставьте это окно открытым во время настройки. Для выхода нажмите Ctrl+C.")
	openBrowser(address)
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	go func() { <-stopped; _ = server.Close() }()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
	}
}
