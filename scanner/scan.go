package scanner

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Result describes one port probe.
type Result struct {
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
	Risk    string `json:"risk,omitempty"`
}

// Options control a scan.
type Options struct {
	Host    string
	Ports   []int
	Workers int
	Timeout time.Duration
	Banner  bool
}

// Scan probes the requested ports concurrently and returns open ports sorted by number.
func Scan(ctx context.Context, o Options) []Result {
	if o.Workers < 1 {
		o.Workers = 100
	}
	if o.Timeout <= 0 {
		o.Timeout = 800 * time.Millisecond
	}
	jobs := make(chan int)
	var mu sync.Mutex
	var open []Result
	var wg sync.WaitGroup
	for i := 0; i < o.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if r, ok := probe(ctx, o, p); ok {
					mu.Lock()
					open = append(open, r)
					mu.Unlock()
				}
			}
		}()
	}
loop:
	for _, p := range o.Ports {
		select {
		case jobs <- p:
		case <-ctx.Done():
			break loop
		}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
}

func probe(ctx context.Context, o Options, port int) (Result, bool) {
	d := net.Dialer{Timeout: o.Timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(o.Host, strconv.Itoa(port)))
	if err != nil {
		return Result{}, false
	}
	defer conn.Close()
	r := Result{Port: port, Open: true, Service: Services[port], Risk: RiskyWhenExposed[port]}
	if o.Banner {
		r.Banner = grab(conn, port, o.Timeout)
	}
	return r, true
}

func grab(conn net.Conn, port int, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if port == 80 || port == 8080 || port == 8000 || port == 3000 {
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return sanitize(string(buf[:n]))
}

func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}
