// Package labels says what a connection was: its scope (local, private,
// public) and, where it can tell, the service behind it — a customer's own
// port name, the program seen listening on that port, or a well-known port.
package labels

import (
	"net/netip"
	"path/filepath"
	"sync"
)

const (
	Local   = "local"
	Private = "private"
	Public  = "public"
)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Scope classifies a destination address. Anything unparseable is public:
// a label must never hide a connection that could matter.
func Scope(addr string) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return Public
	}
	ip = ip.Unmap()
	switch {
	case ip.IsLoopback() || ip.IsUnspecified():
		return Local
	case ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip):
		return Private
	}
	return Public
}

var wellKnown = map[uint32]string{
	22: "ssh", 25: "smtp", 53: "dns", 80: "http", 443: "https", 465: "smtps", 587: "smtp",
	1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker-api", 2376: "docker-api",
	3000: "http-app", 3306: "mysql", 4317: "otlp-grpc", 4318: "otlp-http", 5000: "http-app",
	5432: "postgres", 5672: "rabbitmq", 6333: "qdrant", 6334: "qdrant-grpc", 6379: "redis",
	7687: "neo4j", 8000: "http-app", 8080: "http-app", 8200: "vault", 8443: "https",
	9000: "http-app", 9042: "cassandra", 9092: "kafka", 9200: "elasticsearch",
	11211: "memcached", 11434: "ollama", 19530: "milvus", 27017: "mongodb",
}

// Listener is a program seen starting to listen on a port.
type Listener struct {
	Binary    string
	Container string
}

func (l Listener) Name() string {
	name := filepath.Base(l.Binary)
	if l.Container != "" {
		c := l.Container
		if len(c) > 12 {
			c = c[:12]
		}
		name += " (container " + c + ")"
	}
	return name
}

type Labeler struct {
	custom map[uint32]string
	mu     sync.Mutex
	listen map[uint32]Listener
}

func New(custom map[int]string) *Labeler {
	l := &Labeler{custom: map[uint32]string{}, listen: map[uint32]Listener{}}
	for port, name := range custom {
		if port > 0 && port < 65536 && name != "" {
			l.custom[uint32(port)] = name
		}
	}
	return l
}

// Listening records a program that started listening on port (Tetragon's
// inet_csk_listen_start kprobe), so local connections to it get its name.
func (l *Labeler) Listening(port uint32, who Listener) {
	if port == 0 {
		return
	}
	l.mu.Lock()
	l.listen[port] = who
	l.mu.Unlock()
}

// Service names what is behind addr:port, or "" when unknown. The program
// listening is only trusted for local connections: a remote host's port
// says nothing about which program on this host listens on the same one.
func (l *Labeler) Service(addr string, port uint32) string {
	if name, ok := l.custom[port]; ok {
		return name
	}
	if Scope(addr) == Local {
		l.mu.Lock()
		who, ok := l.listen[port]
		l.mu.Unlock()
		if ok {
			if wk := wellKnown[port]; wk != "" && filepath.Base(who.Binary) != wk {
				return wk + " · " + who.Name()
			}
			return who.Name()
		}
	}
	return wellKnown[port]
}
