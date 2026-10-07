package labels

import "testing"

func TestScope(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1": Local, "::1": Local, "0.0.0.0": Local, "::ffff:127.0.0.1": Local,
		"10.1.2.3": Private, "172.17.0.1": Private, "192.168.1.5": Private, "169.254.1.1": Private,
		"100.64.3.3": Private, "fd00::1": Private,
		"1.1.1.1": Public, "172.65.90.24": Public, "2606:4700::1": Public, "not-an-ip": Public,
	}
	for addr, want := range cases {
		if got := Scope(addr); got != want {
			t.Errorf("Scope(%s) = %s, want %s", addr, got, want)
		}
	}
}

func TestServiceNames(t *testing.T) {
	l := New(map[int]string{7000: "billing-api"})
	l.Listening(6333, Listener{Binary: "/qdrant/qdrant", Container: "1c210c6eff010da34bd4a21e3db8ee0"})
	l.Listening(5432, Listener{Binary: "/usr/local/bin/postgres"})
	l.Listening(9999, Listener{Binary: "/opt/app/server"})
	cases := []struct {
		addr string
		port uint32
		want string
	}{
		{"127.0.0.1", 7000, "billing-api"}, // customer's own name wins
		{"10.0.0.9", 7000, "billing-api"},
		{"127.0.0.1", 6333, "qdrant (container 1c210c6eff01)"}, // seen listening
		{"127.0.0.1", 5432, "postgres"},
		{"127.0.0.1", 9999, "server"},
		{"127.0.0.1", 11434, "ollama"}, // well-known, not seen
		{"172.65.90.24", 443, "https"},
		{"172.65.90.24", 9999, ""}, // a remote port: listener not trusted
		{"8.8.8.8", 12345, ""},
	}
	for _, c := range cases {
		if got := l.Service(c.addr, c.port); got != c.want {
			t.Errorf("Service(%s:%d) = %q, want %q", c.addr, c.port, got, c.want)
		}
	}
	// docker-proxy publishing postgres on the host: both names are useful
	l.Listening(5433, Listener{Binary: "/usr/bin/docker-proxy"})
	l.custom = map[uint32]string{}
	if got := l.Service("127.0.0.1", 5433); got != "docker-proxy" {
		t.Error(got)
	}
	l.Listening(5432, Listener{Binary: "/usr/bin/docker-proxy"})
	if got := l.Service("127.0.0.1", 5432); got != "postgres · docker-proxy" {
		t.Error(got)
	}
}
