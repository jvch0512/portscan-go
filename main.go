package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/jvch0512/portscan-go/scanner"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errw *os.File) int {
	fs := flag.NewFlagSet("portscan", flag.ContinueOnError)
	fs.SetOutput(errw)
	ports := fs.String("p", "top", `ports: "top", "22,80" or "1-1024"`)
	workers := fs.Int("w", 200, "concurrent workers")
	timeout := fs.Duration("t", 800*time.Millisecond, "per-port timeout")
	banner := fs.Bool("b", false, "grab service banners")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(errw, "usage: portscan [flags] <host>   (scan only systems you own or are authorised to test)")
		return 2
	}
	list, err := scanner.ParsePorts(*ports)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 2
	}
	host := fs.Arg(0)
	if _, err := net.LookupHost(host); err != nil {
		fmt.Fprintln(errw, "error: cannot resolve", host)
		return 2
	}
	res := scanner.Scan(context.Background(), scanner.Options{Host: host, Ports: list, Workers: *workers, Timeout: *timeout, Banner: *banner})
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"host": host, "scanned": len(list), "open": res})
		return 0
	}
	fmt.Fprintf(out, "%s: %d/%d ports open\n", host, len(res), len(list))
	for _, r := range res {
		line := fmt.Sprintf("  %5d/tcp  %-14s", r.Port, r.Service)
		if r.Risk != "" {
			line += "  RISK: " + r.Risk
		}
		if r.Banner != "" {
			line += "  | " + r.Banner
		}
		fmt.Fprintln(out, line)
	}
	return 0
}
