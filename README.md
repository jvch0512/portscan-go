# portscan-go

Fast, dependency-free TCP connect scanner written in Go. Concurrent worker pool, optional banner grabbing, service labels and a short list of **services that should rarely be exposed** (Docker API, Redis, memcached, RDP, SMB...).

Single static binary, standard library only, tests run with the race detector.

> Built with AI assistance (Claude) as a portfolio project. Review the code before relying on it.

## Usage

```bash
go install github.com/jvch0512/portscan-go@latest
portscan -p top scanme.nmap.org
portscan -p 1-1024 -b -w 500 192.168.1.10
portscan -p 22,80,443 -json example.org
```

| Flag | Meaning |
|------|---------|
| `-p` | `top`, a list (`22,80`) or ranges (`1-1024`) |
| `-w` | concurrent workers (default 200) |
| `-t` | per-port timeout (default 800ms) |
| `-b` | grab service banners (sanitised to printable ASCII) |
| `-json` | machine-readable output |

## Design notes

* Worker pool fed by a channel; `context` cancellation stops feeding jobs immediately
* Results are collected under a mutex and sorted for deterministic output
* Banner data is stripped of control characters, so hostile services cannot inject terminal escape codes
* Tests spin up real local listeners instead of mocking the network

## Responsible use

Scan only systems you own or are explicitly authorised to test. This is a plain connect scan (no SYN/stealth tricks), comparable to `nmap -sT`.

## Development

```bash
go vet ./... && go test -race ./...
```

MIT licensed.
