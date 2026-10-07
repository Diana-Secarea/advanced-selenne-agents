// Package pipeline turns Tetragon events into Selenne host events.
//
// Tetragon writes its export late and out of order (a file open can land
// before the exec of the process that did it), so events are held for a
// moment and released in time order. Process starts and listening sockets
// update the tables the moment they are read, so a held event always finds
// the process it belongs to. Only agents' events are released; the rest of
// the host is dropped here.
package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/config"
	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/labels"
	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/mask"
	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/procs"
	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/tetragon"
)

// HostEvent is one line of POST /v1/host-events. kind, host, pid and
// ts_unix_nano are what ingest requires; the rest lands in `detail`, and
// path / exe / argv / daddr are what the AG-2xx rules read.
type HostEvent struct {
	Kind        string `json:"kind"` // exec | exit | open | connect | listen | sensor.heartbeat
	Host        string `json:"host"`
	PID         uint32 `json:"pid"`
	PPID        uint32 `json:"ppid,omitempty"`
	TsUnixNano  int64  `json:"ts_unix_nano"`
	EventID     string `json:"event_id"`
	Service     string `json:"service_name,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	ExecID      string `json:"exec_id,omitempty"`
	ProcStartNs int64  `json:"proc_start_ns,omitempty"`
	Exe         string `json:"exe,omitempty"`

	// exec
	AgentRoot bool     `json:"agent_root,omitempty"` // the agent's main process, not one it started
	Argv      []string `json:"argv,omitempty"`
	Cwd       string   `json:"cwd,omitempty"`
	UID       *uint32  `json:"uid,omitempty"`
	// exit
	Status     *uint32 `json:"status,omitempty"`
	Signal     string  `json:"signal,omitempty"`
	DurationMs *int64  `json:"duration_ms,omitempty"`
	// open
	Path string `json:"path,omitempty"`
	// connect / listen
	Protocol    string `json:"protocol,omitempty"`
	Saddr       string `json:"saddr,omitempty"`
	Sport       uint32 `json:"sport,omitempty"`
	Daddr       string `json:"daddr,omitempty"`
	Dport       uint32 `json:"dport,omitempty"`
	Scope       string `json:"scope,omitempty"`        // local | private | public
	DestService string `json:"dest_service,omitempty"` // ollama, postgres, qdrant (container …)

	SensorVersion string         `json:"sensor_version,omitempty"`
	Stats         map[string]any `json:"stats,omitempty"` // heartbeat only
}

type held struct {
	ev  tetragon.Event
	pos tetragon.Position // where its line starts, to resume from after a crash
	seq uint64            // read order
}

// Stats counts what the pipeline did since start.
type Stats struct {
	Read, Released, Dropped, Unparsed int64
}

type Pipeline struct {
	cfg     config.Config
	version string
	procs   *procs.Table
	labels  *labels.Labeler
	held    []held
	seq     uint64
	latest  time.Time // newest event time read
	lastAdd time.Time // wall clock of the last read
	Stats   Stats
}

func New(cfg config.Config, version string) *Pipeline {
	return &Pipeline{cfg: cfg, version: version, procs: procs.New(cfg.Agents),
		labels: labels.New(cfg.Network.PortLabels)}
}

func (p *Pipeline) Procs() *procs.Table { return p.procs }

// Learn updates the process and listener tables without holding the event
// for release: replaying history after a restart.
func (p *Pipeline) Learn(ev tetragon.Event) {
	switch {
	case ev.Exec != nil:
		p.procs.Exec(&ev.Exec.Process, ev.Exec.Parent)
	case ev.Exit != nil:
		p.procs.Exit(&ev.Exit.Process, ev.Time)
	case ev.Kprobe != nil && ev.Kprobe.FunctionName == "inet_csk_listen_start":
		p.learnListener(ev)
	}
}

// Add takes one event as read from the export; pos is where its line starts.
func (p *Pipeline) Add(ev tetragon.Event, pos tetragon.Position) {
	p.Stats.Read++
	p.lastAdd = time.Now()
	if ev.Time.After(p.latest) {
		p.latest = ev.Time
	}
	if ev.Process() == nil {
		p.Stats.Dropped++
		return
	}
	switch {
	case ev.Exec != nil:
		p.procs.Exec(&ev.Exec.Process, ev.Exec.Parent)
	case ev.Kprobe != nil && ev.Kprobe.FunctionName == "inet_csk_listen_start":
		p.learnListener(ev)
	}
	p.seq++
	p.held = append(p.held, held{ev, pos, p.seq})
}

func (p *Pipeline) learnListener(ev tetragon.Event) {
	pr := &ev.Kprobe.Process
	for _, a := range ev.Kprobe.Args {
		if a.SockArg != nil {
			who := labels.Listener{Binary: pr.Binary, Container: pr.ContainerID()}
			if who.Binary == "" { // unenriched: the table may know it
				if known := p.procs.Resolve(pr, ev.Time); known != nil {
					who = labels.Listener{Binary: known.Binary, Container: known.Container}
				}
			}
			p.labels.Listening(a.SockArg.Sport, who)
		}
	}
}

// Release returns, in time order and as host events (agents' only), the
// held events that can no longer be overtaken: older than the newest event
// read minus the hold. Measured against what was read rather than the clock,
// so catching up on a backlog re-sorts it just the same. Once nothing new has
// been read for a full hold, everything held goes: there is nothing to wait for.
func (p *Pipeline) Release(now time.Time) []HostEvent {
	return p.release(now, false)
}

func (p *Pipeline) release(now time.Time, flushing bool) []HostEvent {
	ref := p.latest // "now" in event time
	cutoff := ref.Add(-p.cfg.Shipping.Hold)
	if flushing || now.Sub(p.lastAdd) >= p.cfg.Shipping.Hold {
		ref, cutoff = now, now.Add(time.Duration(1)<<62)
	}
	sort.SliceStable(p.held, func(i, j int) bool { return p.held[i].ev.Time.Before(p.held[j].ev.Time) })
	n := sort.Search(len(p.held), func(i int) bool { return p.held[i].ev.Time.After(cutoff) })
	var out []HostEvent
	var waiting []held
	for _, h := range p.held[:n] {
		pr := p.procs.Resolve(h.ev.Process(), h.ev.Time)
		// Tetragon can write a process's start well after its file and
		// network events (30 s seen on WSL2): an event whose process is not
		// known yet waits for it, up to max_wait
		if pr == nil && !flushing && ref.Sub(h.ev.Time) < p.cfg.Shipping.MaxWait {
			waiting = append(waiting, h)
			continue
		}
		if he, ok := p.convert(h.ev, pr); ok {
			out = append(out, he)
			p.Stats.Released++
		} else {
			p.Stats.Dropped++
		}
		// every host process is tracked (to know agents' descendants); its
		// exit, in time order, is what lets Prune forget it later
		if h.ev.Exit != nil {
			p.procs.Exit(&h.ev.Exit.Process, h.ev.Time)
		}
	}
	if n > 0 {
		// exited processes stay resolvable for a while after the last event
		// released (event time, so a backlog does not prune what it needs)
		p.procs.Prune(p.held[n-1].ev.Time.Add(-p.cfg.Shipping.MaxWait - 5*time.Minute))
	}
	p.held = append(waiting, p.held[n:]...)
	return out
}

// Flush releases everything still held (shutdown).
func (p *Pipeline) Flush() []HostEvent { return p.release(time.Now(), true) }

// Pending is where the earliest-read event still held starts, if any: a
// restart must re-read from there, so it is the position safe to save.
func (p *Pipeline) Pending() (tetragon.Position, bool) {
	var first *held
	for i := range p.held {
		if first == nil || p.held[i].seq < first.seq {
			first = &p.held[i]
		}
	}
	if first == nil {
		return tetragon.Position{}, false
	}
	return first.pos, true
}

func (p *Pipeline) Held() int { return len(p.held) }

// eventID is stable for a given export line, so re-reading the file after
// a crash produces the same ids and ingest drops the duplicates.
func eventID(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:12])
}

func (p *Pipeline) convert(ev tetragon.Event, pr *procs.Proc) (HostEvent, bool) {
	tp := ev.Process()
	if !pr.Agent() {
		return HostEvent{}, false
	}
	he := HostEvent{Host: p.cfg.Host, PID: pr.PID, PPID: pr.ParentPID, TsUnixNano: ev.Time.UnixNano(),
		EventID: eventID(ev.Raw), Service: pr.Service, ContainerID: pr.Container, ExecID: pr.ExecID,
		Exe: pr.Binary, SensorVersion: p.version}
	if !pr.Start.IsZero() {
		he.ProcStartNs = pr.Start.UnixNano()
	}
	switch {
	case ev.Exec != nil:
		he.Kind = "exec"
		he.AgentRoot = pr.Root
		he.Argv = mask.Argv(append([]string{tp.Binary}, tetragon.SplitArgs(tp.Arguments)...))
		he.Cwd, he.UID = tp.CWD, tp.UID
	case ev.Exit != nil:
		he.Kind = "exit"
		status := ev.Exit.Status
		he.Status, he.Signal = &status, ev.Exit.Signal
		if !pr.Start.IsZero() {
			d := ev.Time.Sub(pr.Start).Milliseconds()
			he.DurationMs = &d
		}
	case ev.Kprobe != nil:
		return p.convertKprobe(ev, he)
	default:
		return he, false
	}
	return he, true
}

func (p *Pipeline) convertKprobe(ev tetragon.Event, he HostEvent) (HostEvent, bool) {
	k := ev.Kprobe
	for _, a := range k.Args {
		switch {
		case a.FileArg != nil:
			if !p.fileWanted(a.FileArg) {
				return he, false
			}
			he.Kind, he.Path = "open", a.FileArg.Path
			return he, true
		case a.SockArg != nil:
			s := a.SockArg
			he.Protocol = strings.TrimPrefix(s.Protocol, "IPPROTO_")
			he.Saddr, he.Sport = s.Saddr, s.Sport
			if k.FunctionName == "inet_csk_listen_start" {
				he.Kind = "listen"
				he.Scope = labels.Scope(s.Saddr)
				he.DestService = p.labels.Service(s.Saddr, s.Sport)
				return he, true
			}
			he.Kind, he.Daddr, he.Dport = "connect", s.Daddr, s.Dport
			he.Scope = labels.Scope(s.Daddr)
			if !p.scopeWanted(he.Scope) {
				return he, false
			}
			he.DestService = p.labels.Service(s.Daddr, s.Dport)
			return he, true
		}
	}
	return he, false
}

// a shared library with a version: libssl.so.3, libpq-9b38f5e3.so.5.17
var sharedLib = regexp.MustCompile(`\.so(\.[0-9]+)+$`)

// fileWanted applies the file filters the kernel cannot (see config.Files).
func (p *Pipeline) fileWanted(f *tetragon.FileArg) bool {
	fc := p.cfg.Files
	if !fc.Enabled {
		return false
	}
	for _, s := range fc.Sensitive {
		if strings.HasSuffix(f.Path, s) {
			return true
		}
	}
	if fc.SkipDirectories && strings.HasPrefix(f.Permission, "d") {
		return false
	}
	for _, s := range fc.SkipContains {
		if strings.Contains(f.Path, s) {
			return false
		}
	}
	return !sharedLib.MatchString(f.Path)
}

func (p *Pipeline) scopeWanted(scope string) bool {
	switch scope {
	case labels.Local:
		return p.cfg.Network.Local
	case labels.Private:
		return p.cfg.Network.Private
	}
	return p.cfg.Network.Public
}
