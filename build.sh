#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$project_dir/dist" "$project_dir/windows/setup/payload"

(
  cd "$project_dir/windows/bridge"
  go test ./...
  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -H windowsgui' \
    -o "$project_dir/windows/setup/payload/privetdns-bridge.exe" .
)
cp "$project_dir/windows/bridge/smartdns-domains.txt" "$project_dir/windows/setup/payload/smartdns-domains.txt"
(
  cd "$project_dir/windows/setup"
  go run github.com/akavel/rsrc@v0.10.2 -arch amd64 \
    -ico PrivetDNS-Setup.ico -manifest PrivetDNS-Setup.exe.manifest -o rsrc_windows.syso
  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -H windowsgui' \
    -o "$project_dir/dist/PrivetDNS-Connect-Windows-x64.exe" .
)
(
  cd "$project_dir/linux"
  go test ./...
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
    -o "$project_dir/dist/PrivetDNS-Connect" .
)
cp "$project_dir/linux/README.md" "$project_dir/dist/README-Linux.md"
(
  cd "$project_dir/dist"
  python3 -m zipfile -c PrivetDNS-Connect-Arch-x64.zip PrivetDNS-Connect README-Linux.md
)
sha256sum "$project_dir/dist/PrivetDNS-Connect-Windows-x64.exe" "$project_dir/dist/PrivetDNS-Connect-Arch-x64.zip"
