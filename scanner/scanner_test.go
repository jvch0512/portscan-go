package scanner

import (
	"context"
	"net"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("80, 22,8000-8002,22")
	if err != nil || !reflect.DeepEqual(got, []int{22, 80, 8000, 8001, 8002}) {
		t.Fatalf("got %v err %v", got, err)
	}
	if top, _ := ParsePorts("top"); len(top) != len(TopPorts) {
		t.Fatal("top list wrong")
	}
	for _, bad := range []string{"0", "70000", "abc", "10-5", "1-99999", "80,,"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func listen(t *testing.T, banner string) (int, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if banner != "" {
				c.Write([]byte(banner))
			}
			c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, func() { l.Close() }
}

func TestScanFindsOnlyOpenPorts(t *testing.T) {
	p1, c1 := listen(t, "")
	p2, c2 := listen(t, "")
	defer c1()
	defer c2()
	closed, cc := listen(t, "")
	cc() // closed immediately
	res := Scan(context.Background(), Options{Host: "127.0.0.1", Ports: []int{p1, p2, closed}, Workers: 4, Timeout: time.Second})
	ports := map[int]bool{}
	for _, r := range res {
		ports[r.Port] = true
	}
	if !ports[p1] || !ports[p2] || ports[closed] || len(res) != 2 {
		t.Fatalf("unexpected %+v (p1=%d p2=%d closed=%d)", res, p1, p2, closed)
	}
	if res[0].Port > res[1].Port {
		t.Fatal("results not sorted")
	}
}

func TestBannerGrabIsSanitised(t *testing.T) {
	p, stop := listen(t, "SSH-2.0-OpenSSH_9.6\r\n\x00\x01")
	defer stop()
	res := Scan(context.Background(), Options{Host: "127.0.0.1", Ports: []int{p}, Timeout: time.Second, Banner: true})
	if len(res) != 1 || res[0].Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("banner %+v", res)
	}
}

func TestContextCancelStopsScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ports := make([]int, 0, 1000)
	for i := 1; i <= 1000; i++ {
		ports = append(ports, i)
	}
	start := time.Now()
	Scan(ctx, Options{Host: "127.0.0.1", Ports: ports, Workers: 2, Timeout: time.Second})
	if time.Since(start) > 2*time.Second {
		t.Fatal("scan ignored cancellation")
	}
}

func TestServiceAndRiskLabels(t *testing.T) {
	if Services[22] != "ssh" || RiskyWhenExposed[2375] == "" {
		t.Fatal("labels missing")
	}
	_ = strconv.Itoa
}
