package procs

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/config"
	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/tetragon"
)

var t0 = time.Date(2026, 10, 7, 20, 57, 54, 0, time.UTC)

func execID(pid uint32, ktime int) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("node:%d:%d", ktime, pid)))
}

func proc(pid, parent uint32, at time.Duration, env ...string) *tetragon.Process {
	p := &tetragon.Process{ExecID: execID(pid, int(at)+1), PID: pid, Binary: "/usr/bin/x",
		StartTime: t0.Add(at), ParentExecID: execID(parent, 0)} // parent unresolved, as on WSL2
	for i := 0; i+1 < len(env); i += 2 {
		p.Env = append(p.Env, tetragon.EnvVar{Key: env[i], Value: env[i+1]})
	}
	return p
}

func table() *Table {
	cfg := config.Default().Agents
	return New(cfg)
}

func TestZeroConfigAgentAndItsChildren(t *testing.T) {
	tb := table()
	agent := tb.Exec(proc(100, 1, 0, "OTEL_SERVICE_NAME", "cve-agent"), nil)
	child := tb.Exec(proc(101, 100, time.Second, "OTEL_SERVICE_NAME", "cve-agent"), nil)
	cleared := tb.Exec(proc(102, 101, 2*time.Second), nil) // env wiped by the tool
	other := tb.Exec(proc(200, 1, 0), nil)
	if agent.Service != "cve-agent" || child.Service != "cve-agent" || cleared.Service != "cve-agent" {
		t.Fatalf("agent tree: %q %q %q", agent.Service, child.Service, cleared.Service)
	}
	if other.Agent() {
		t.Fatal("unrelated process counted as an agent")
	}
	if got := tb.Agents(); got["cve-agent"] != 3 || len(got) != 1 {
		t.Fatal(got)
	}
}

func TestResourceAttributes(t *testing.T) {
	p := proc(1, 0, 0, "OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=prod, service.name = support-bot")
	if s := ServiceFromEnv(p); s != "support-bot" {
		t.Fatal(s)
	}
}

func TestIgnoredInfrastructure(t *testing.T) {
	tb := table()
	// dockerd sets OTEL_SERVICE_NAME=dockerd on iptables, docker-proxy, ...
	if pr := tb.Exec(proc(300, 1, 0, "OTEL_SERVICE_NAME", "dockerd"), nil); pr.Agent() {
		t.Fatal("dockerd's children are not agents")
	}
}

func TestMatchRules(t *testing.T) {
	cfg := config.Default().Agents
	cfg.Match = []config.AgentRule{{Service: "legacy-bot", Binary: `/python3?$`, Args: `bot\.py`}}
	c := config.Config{Agents: cfg, Ingest: config.Ingest{URL: "http://x"}, Shipping: config.Default().Shipping}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	tb := New(c.Agents)
	p := proc(400, 1, 0)
	p.Binary, p.Arguments = "/usr/bin/python3", "bot.py --serve"
	if s := tb.Exec(p, nil).Service; s != "legacy-bot" {
		t.Fatal(s)
	}
	q := proc(401, 1, 0)
	q.Binary, q.Arguments = "/usr/bin/python3", "other.py"
	if tb.Exec(q, nil).Agent() {
		t.Fatal("args must match too")
	}
}

func TestResolveUnenrichedEventsByPidAndTime(t *testing.T) {
	tb := table()
	old := tb.Exec(proc(500, 1, 0), nil) // pid 500, not an agent
	tb.Exit(&tetragon.Process{ExecID: old.ExecID, PID: 500}, t0.Add(time.Second))
	agent := tb.Exec(proc(500, 1, 5*time.Second, "OTEL_SERVICE_NAME", "a"), nil) // pid reused
	unknown := &tetragon.Process{PID: 500}                                       // kprobe without exec_id
	if got := tb.Resolve(unknown, t0.Add(500*time.Millisecond)); got != old {
		t.Fatal("event before the reuse belongs to the old process")
	}
	if got := tb.Resolve(unknown, t0.Add(6*time.Second)); got != agent {
		t.Fatal("event after the reuse belongs to the agent")
	}
	if got := tb.Resolve(&tetragon.Process{PID: 999}, t0); got != nil {
		t.Fatal("unknown pid resolves to nothing")
	}
}

func TestPruneKeepsLiveProcesses(t *testing.T) {
	tb := table()
	a := tb.Exec(proc(600, 1, 0), nil)
	tb.Exec(proc(601, 1, 0), nil)
	tb.Exit(&tetragon.Process{ExecID: a.ExecID, PID: 600}, t0)
	if n := tb.Prune(t0.Add(time.Minute)); n != 1 || tb.Len() != 1 {
		t.Fatal(n, tb.Len())
	}
}

func TestReplayedExecIsNotDuplicated(t *testing.T) {
	tb := table()
	p := proc(700, 1, 0, "OTEL_SERVICE_NAME", "a")
	first := tb.Exec(p, nil)
	if tb.Exec(p, nil) != first || tb.Len() != 1 {
		t.Fatal("replay added a second process")
	}
}

func TestRootIsTheAgentsMainProcess(t *testing.T) {
	tb := table()
	at := func(pid, parent uint32, d time.Duration, bin string) *Proc {
		p := proc(pid, parent, d, "OTEL_SERVICE_NAME", "cve-agent")
		p.Binary = bin
		return tb.Exec(p, nil)
	}
	wrapper := at(800, 1, 0, "/usr/bin/timeout")           // started by a non-agent
	main := at(801, 800, time.Second, "/venv/bin/python3") // what timeout launched
	tool := at(802, 801, 2*time.Second, "/usr/bin/curl")   // what the agent started
	again := at(803, 802, 3*time.Second, "/usr/bin/env")   // a wrapper inside the agent: not root
	if !wrapper.Root || !main.Root || tool.Root || again.Root {
		t.Fatalf("roots: timeout %v, python3 %v, curl %v, env %v", wrapper.Root, main.Root, tool.Root, again.Root)
	}
	if tb.Exec(proc(900, 1, 0), nil).Root {
		t.Fatal("a non-agent is never an agent root")
	}
}

// Seen on selenne-prod: containerd sets OTEL_SERVICE_NAME=containerd-shim-<id>
// on each shim, and everything it started inside containers followed it.
func TestContainerdShimsAndContainerBoundaries(t *testing.T) {
	tb := table()
	shim := tb.Exec(proc(1000, 1, 0, "OTEL_SERVICE_NAME", "containerd-shim-7aeabea352a0dedf"), nil)
	runc := tb.Exec(proc(1001, 1000, time.Second), nil) // env cleared, parent is the shim
	if shim.Agent() || runc.Agent() {
		t.Fatalf("shim %q runc %q", shim.Service, runc.Service)
	}
	// an agent on the host that launches a container: the container's
	// processes are not the agent's
	agent := tb.Exec(proc(1100, 1, 0, "OTEL_SERVICE_NAME", "bot"), nil)
	inBox := proc(1101, 1100, time.Second)
	inBox.Docker = "facb8fcb8a12df7ee5c53aade12edb8"
	if !agent.Agent() || tb.Exec(inBox, nil).Agent() {
		t.Fatal("agent status crossed into a container")
	}
	// an agent inside a container: its children in the same container count
	boxed := proc(1200, 1, 0, "OTEL_SERVICE_NAME", "boxed-bot")
	boxed.Docker = "1c210c6eff010da34bd4a21e3db8ee0"
	tb.Exec(boxed, nil)
	child := proc(1201, 1200, time.Second)
	child.Docker = boxed.Docker
	if s := tb.Exec(child, nil).Service; s != "boxed-bot" {
		t.Fatalf("same-container child: %q", s)
	}
	// an ignored service never inherits from an agent parent either
	ign := tb.Exec(proc(1102, 1100, 2*time.Second, "OTEL_SERVICE_NAME", "dockerd"), nil)
	if ign.Agent() {
		t.Fatal("an ignored service inherited agent status")
	}
}

func TestDefaultIgnoreListCoversCommonRuntimes(t *testing.T) {
	tb := table()
	for i, name := range []string{"containerd", "containerd-shim-abc", "containerd-shim-runc-v2", "conmon-1234",
		"podman-system", "crio", "kubelet", "k3s-server", "rke2-agent", "tetragon"} {
		if tb.Exec(proc(uint32(2000+i), 1, 0, "OTEL_SERVICE_NAME", name), nil).Agent() {
			t.Errorf("%s counted as an agent", name)
		}
	}
	if !tb.Exec(proc(2100, 1, 0, "OTEL_SERVICE_NAME", "containers-bot"), nil).Agent() {
		t.Error("a real agent whose name merely starts like a runtime was ignored")
	}
}
