package pipeline

import (
	"bufio"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/config"
	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/tetragon"
)

// testdata/spike.jsonl: real Tetragon output from the WSL2 spike, in the
// export's own order — the fake agent, the CVE agent, a control process
// reading a fake key without OTel variables, dockerd's children and
// unrelated container traffic.
func loadSpike(t *testing.T, p *Pipeline) {
	t.Helper()
	f, err := os.Open("../../testdata/spike.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	var off int64
	for sc.Scan() {
		line := slices.Clone(sc.Bytes())
		ev, err := tetragon.Parse(line)
		if err != nil {
			t.Fatal(err)
		}
		p.Add(ev, tetragon.Position{Path: "spike.jsonl", Offset: off})
		off += int64(len(line)) + 1
	}
}

func newPipeline() *Pipeline {
	cfg := config.Default()
	cfg.Host = "dev-box"
	return New(cfg, "test")
}

func TestSpikeCaptureBecomesAgentEventsOnly(t *testing.T) {
	p := newPipeline()
	loadSpike(t, p)
	out := p.Flush()

	type key struct{ service, kind string }
	got := map[key]int{}
	for i, e := range out {
		got[key{e.Service, e.Kind}]++
		if i > 0 && e.TsUnixNano < out[i-1].TsUnixNano {
			t.Fatal("events not released in time order")
		}
		if e.Host != "dev-box" || e.EventID == "" || e.SensorVersion != "test" {
			t.Fatalf("missing fields: %+v", e)
		}
	}
	want := map[key]int{
		{"spike-agent", "exec"}:    5, // python, sh, cat, curl, sh -c "… | sh"
		{"spike-agent", "open"}:    6, // writes + reads of the fake secrets, cat .env
		{"spike-agent", "connect"}: 2, // curl → example.com, python → 1.1.1.1
		{"cve-agent", "exec"}:      2, // timeout wrapper + python
		{"cve-agent", "connect"}:   1, // NVD
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%v: got %d, want %d (all: %v)", k, got[k], n, got)
		}
	}
	for k := range got {
		if k.service != "spike-agent" && k.service != "cve-agent" {
			t.Errorf("non-agent event released: %v", k) // control, dockerd, containers
		}
	}
}

func TestSpikeEventDetails(t *testing.T) {
	p := newPipeline()
	loadSpike(t, p)
	var opens []string
	var connects, cmds []HostEvent
	for _, e := range p.Flush() {
		switch e.Kind {
		case "open":
			opens = append(opens, e.Path)
			if e.PID == 0 || e.Exe == "" {
				t.Errorf("open not linked to its process: %+v", e)
			}
		case "connect":
			connects = append(connects, e)
		case "exec":
			cmds = append(cmds, e)
		}
	}
	if !slices.ContainsFunc(opens, func(s string) bool { return strings.HasSuffix(s, "/.ssh/id_rsa") }) {
		t.Error("the .ssh/id_rsa read is missing:", opens)
	}
	for _, c := range connects {
		if c.Daddr == "1.1.1.1" && (c.Scope != "public" || c.DestService != "https" || c.Dport != 443) {
			t.Errorf("1.1.1.1 labels: %+v", c)
		}
	}
	// the "curl … | sh" command line arrives as argv, ready for AG-202
	found := false
	for _, c := range cmds {
		if len(c.Argv) == 3 && c.Argv[1] == "-c" && strings.Contains(c.Argv[2], "| sh") {
			found = true
		}
	}
	if !found {
		t.Error("sh -c '… | sh' argv not found")
	}
	// main processes: the fake agent's python3; the CVE agent's timeout and
	// the python3 it launched. What they started is not.
	for _, c := range cmds {
		want := c.Exe == "/usr/bin/python3" || c.Service == "cve-agent"
		if c.AgentRoot != want {
			t.Errorf("agent_root of %s (%s) = %v", c.Exe, c.Service, c.AgentRoot)
		}
	}
}

func TestEventIDsAreStableAcrossRuns(t *testing.T) {
	a, b := newPipeline(), newPipeline()
	loadSpike(t, a)
	loadSpike(t, b)
	ea, eb := a.Flush(), b.Flush()
	seen := map[string]bool{}
	for i := range ea {
		if ea[i].EventID != eb[i].EventID {
			t.Fatal("event id changed between runs: a re-read after a crash would duplicate")
		}
		if seen[ea[i].EventID] {
			t.Fatal("duplicate event id", ea[i].EventID)
		}
		seen[ea[i].EventID] = true
	}
}

func TestHoldAndPendingOffset(t *testing.T) {
	p := newPipeline()
	loadSpike(t, p)
	newest := p.latest
	// everything has just been read: only events more than the hold older
	// than the newest one read can go
	first := p.Release(time.Now())
	limit := newest.Add(-p.cfg.Shipping.Hold).UnixNano()
	for _, e := range first {
		if e.TsUnixNano > limit {
			t.Fatalf("released inside the hold: %+v", e)
		}
	}
	pos, ok := p.Pending()
	if len(first) == 0 || p.Held() == 0 || !ok || pos.Offset <= 0 {
		t.Fatalf("released %d, held %d, pending %v %v", len(first), p.Held(), pos, ok)
	}
	// nothing new arrives for a full hold: the rest goes too
	p.Release(time.Now().Add(11 * time.Second))
	if _, ok := p.Pending(); ok || p.Held() != 0 {
		t.Fatalf("still holding %d", p.Held())
	}
}

func TestScopeSettings(t *testing.T) {
	cfg := config.Default()
	cfg.Network.Public = false
	p := New(cfg, "test")
	loadSpike(t, p)
	for _, e := range p.Flush() {
		if e.Kind == "connect" {
			t.Fatalf("public connect kept with public: false: %+v", e)
		}
	}
}

// Seen end to end on WSL2: Tetragon wrote an agent's exec ~30 s after the
// file opens it did. The opens must wait for it, not be dropped as unknown.
func TestEventsWaitForALateExec(t *testing.T) {
	p := newPipeline()
	t0 := time.Date(2026, 10, 7, 21, 22, 45, 0, time.UTC)
	open := func(pid uint32, at time.Time, path string) tetragon.Event {
		return tetragon.Event{Time: at, Raw: []byte(path), Kprobe: &tetragon.ProcessKprobe{
			Process: tetragon.Process{PID: pid}, FunctionName: "security_file_open",
			Args: []tetragon.KprobeArg{{FileArg: &tetragon.FileArg{Path: path}}}}}
	}
	exec := func(pid uint32, at time.Time, service string) tetragon.Event {
		pr := tetragon.Process{ExecID: fmt.Sprintf("x%d", pid), PID: pid, Binary: "/usr/bin/python3", StartTime: at}
		if service != "" {
			pr.Env = []tetragon.EnvVar{{Key: "OTEL_SERVICE_NAME", Value: service}}
		}
		return tetragon.Event{Time: at, Raw: []byte(pr.ExecID), Exec: &tetragon.ProcessExec{Process: pr}}
	}
	pos := tetragon.Position{}
	p.Add(open(900, t0, "/tmp/h/.ssh/id_rsa"), pos)   // the agent's open, process not known yet
	p.Add(open(950, t0, "/tmp/never-started"), pos)   // a process whose start never comes
	p.Add(exec(901, t0.Add(30*time.Second), ""), pos) // the stream moves on 30 s
	if got := p.Release(time.Now()); len(got) != 0 {
		t.Fatalf("released before the process was known: %+v", got)
	}
	if p.Held() != 3 { // both opens waiting, the newest exec inside the hold
		t.Fatalf("held %d", p.Held())
	}
	p.Add(exec(900, t0.Add(-time.Second), "spike-agent"), pos) // the late exec
	got := p.Release(time.Now())
	var opens []string
	for _, e := range got {
		if e.Kind == "open" {
			opens = append(opens, e.Path)
		}
	}
	if len(opens) != 1 || opens[0] != "/tmp/h/.ssh/id_rsa" {
		t.Fatalf("the agent's open was not released once its exec arrived: %+v", got)
	}
	// the other one gives up after max_wait (60 s of stream time)
	p.Add(exec(902, t0.Add(75*time.Second), ""), pos)
	before := p.Stats.Dropped
	p.Release(time.Now())
	if p.Stats.Dropped <= before || p.Held() != 1 {
		t.Fatalf("the never-started process's open should be dropped: held %d", p.Held())
	}
}
