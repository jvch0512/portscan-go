// Package scanner implements a concurrent TCP connect scanner with banner grabbing.
package scanner

import (
	"fmt"
	"strconv"
	"strings"
)

// TopPorts is a short list of commonly exposed services.
var TopPorts = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 993, 995,
	1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5672, 5900, 6379, 8000, 8080, 8443, 9200, 11211, 27017}

// Services maps well-known ports to service names.
var Services = map[int]string{21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
	111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap", 443: "https", 445: "smb",
	465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
	2049: "nfs", 2375: "docker", 3306: "mysql", 3389: "rdp", 5432: "postgres", 5672: "amqp",
	5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
	11211: "memcached", 27017: "mongodb"}

// RiskyWhenExposed lists services that should rarely be reachable from the internet.
var RiskyWhenExposed = map[int]string{23: "cleartext remote shell", 2375: "unauthenticated Docker API",
	6379: "Redis without auth is common", 11211: "memcached amplification", 27017: "MongoDB", 9200: "Elasticsearch",
	3389: "RDP brute force target", 445: "SMB", 5900: "VNC"}

// ParsePorts parses "22,80,8000-8010" or "top" into a sorted, de-duplicated list.
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "top" || spec == "" {
		return append([]int(nil), TopPorts...), nil
	}
	seen := map[int]bool{}
	var out []int
	add := func(p int) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := strconv.Atoi(lo)
			b, err2 := strconv.Atoi(hi)
			if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			for p := a; p <= b; p++ {
				add(p)
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		add(p)
	}
	sortInts(out)
	return out, nil
}

func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}
