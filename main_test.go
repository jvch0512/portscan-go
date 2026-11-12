package main

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestRunJSONAndUsage(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	f, _ := os.CreateTemp(t.TempDir(), "out")
	defer f.Close()
	if code := run([]string{"-p", port, "-json", "127.0.0.1"}, f, os.Stderr); code != 0 {
		t.Fatalf("exit %d", code)
	}
	b, _ := os.ReadFile(f.Name())
	if !strings.Contains(string(b), `"port": `+port) {
		t.Fatalf("json missing port: %s", b)
	}
	if run([]string{}, f, f) != 2 || run([]string{"-p", "abc", "127.0.0.1"}, f, f) != 2 {
		t.Fatal("bad usage should exit 2")
	}
}
