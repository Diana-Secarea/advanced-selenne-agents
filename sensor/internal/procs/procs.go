// Package procs keeps track of the processes Tetragon reports and decides
// which ones belong to an agent.
//
// A process is an agent when it was started with OTEL_SERVICE_NAME (or
// service.name in OTEL_RESOURCE_ATTRIBUTES), unless that service is on the
// ignore list, or when a configured match rule fits it. A child of an agent
// belongs to that agent. Environment variables are inherited, so most
// children say so themselves; the parent link covers the rest.
package procs

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/config"
	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/tetragon"
)

type Proc struct {
	ExecID    string
	PID       uint32
	ParentPID uint32
	Binary    string
	Args      string
	Container string
	Start     time.Time
	Service   string // the agent it belongs to; "" when it is not an agent
	Root      bool   // the agent's main process, not something the agent started
	Exited    time.Time
}

// wrappers only launch the program they are given: `timeout 300 python3 -m
// agent` makes python3 — not timeout — the agent's main process too.
var wrappers = map[string]bool{"timeout": true, "env": true, "nohup": true, "nice": true,
	"ionice": true, "stdbuf": true, "setsid": true, "tini": true, "dumb-init": true,
	"runuser": true, "su-exec": true, "gosu": true, "chpst": true, "taskset": true}

func (p *Proc) Agent() bool { return p != nil && p.Service != "" }

type Table struct {
	cfg    config.Agents
	ignore map[string]bool
	byExec map[string]*Proc
	byPID  map[uint32][]*Proc // oldest start first
}

func New(cfg config.Agents) *Table {
	t := &Table{cfg: cfg, ignore: map[string]bool{},
		byExec: map[string]*Proc{}, byPID: map[uint32][]*Proc{}}
	for _, s := range cfg.IgnoreServices {
		t.ignore[s] = true
	}
	return t
}

// ServiceFromEnv reads the OTel service name the process was started with.
func ServiceFromEnv(p *tetragon.Process) string {
	if s := strings.TrimSpace(p.EnvValue("OTEL_SERVICE_NAME")); s != "" {
		return s
	}
	for _, part := range strings.Split(p.EnvValue("OTEL_RESOURCE_ATTRIBUTES"), ",") {
		k, v, _ := strings.Cut(part, "=")
		if strings.TrimSpace(k) == "service.name" && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// Exec records a process start and returns it, with its agent decided.
func (t *Table) Exec(p *tetragon.Process, parent *tetragon.Process) *Proc {
	if old, ok := t.byExec[p.ExecID]; ok && p.ExecID != "" {
		return old // the same exec seen twice (a replay after restart)
	}
	pr := &Proc{ExecID: p.ExecID, PID: p.PID, Binary: p.Binary, Args: p.Arguments,
		Container: p.ContainerID(), Start: p.StartTime}
	if parent != nil && parent.PID != 0 {
		pr.ParentPID = parent.PID
	} else if pid, ok := tetragon.ExecIDPID(p.ParentExecID); ok {
		pr.ParentPID = pid
	}
	pr.Service = t.decide(p, pr)
	if pr.Agent() {
		parent := t.parentOf(p, pr)
		pr.Root = parent == nil || parent.Service != pr.Service ||
			(parent.Root && wrappers[filepath.Base(parent.Binary)])
	}
	if pr.ExecID != "" {
		t.byExec[pr.ExecID] = pr
	}
	list := append(t.byPID[pr.PID], pr)
	sort.SliceStable(list, func(i, j int) bool { return list[i].Start.Before(list[j].Start) })
	t.byPID[pr.PID] = list
	return pr
}

func (t *Table) decide(p *tetragon.Process, pr *Proc) string {
	if t.cfg.ZeroConfig {
		if s := ServiceFromEnv(p); s != "" && !t.ignore[s] {
			return s
		}
	}
	for i := range t.cfg.Match {
		if t.cfg.Match[i].Matches(p.Binary, p.Arguments) {
			return t.cfg.Match[i].Service
		}
	}
	// a child of an agent is part of it, even if its environment was cleared
	if parent := t.parentOf(p, pr); parent.Agent() {
		return parent.Service
	}
	return ""
}

func (t *Table) parentOf(p *tetragon.Process, pr *Proc) *Proc {
	if parent, ok := t.byExec[p.ParentExecID]; ok {
		return parent
	}
	if pr.ParentPID != 0 {
		return t.byPIDAt(pr.ParentPID, pr.Start)
	}
	return nil
}

// Resolve finds the process an event belongs to: by exec id when Tetragon
// knew the process, otherwise the latest process with that pid started at
// or before the event (Tetragon could not enrich it — seen on WSL2).
func (t *Table) Resolve(p *tetragon.Process, at time.Time) *Proc {
	if p.ExecID != "" {
		if pr, ok := t.byExec[p.ExecID]; ok {
			return pr
		}
	}
	return t.byPIDAt(p.PID, at)
}

func (t *Table) byPIDAt(pid uint32, at time.Time) *Proc {
	list := t.byPID[pid]
	for i := len(list) - 1; i >= 0; i-- {
		if !list[i].Start.After(at) {
			return list[i]
		}
	}
	return nil
}

// Exit marks a process as ended; it stays resolvable for a while, since
// events about it can still arrive (the export is out of order).
func (t *Table) Exit(p *tetragon.Process, at time.Time) *Proc {
	pr := t.Resolve(p, at)
	if pr != nil {
		pr.Exited = at
	}
	return pr
}

// Prune forgets processes that exited before cutoff.
func (t *Table) Prune(cutoff time.Time) int {
	n := 0
	for pid, list := range t.byPID {
		kept := list[:0]
		for _, pr := range list {
			if !pr.Exited.IsZero() && pr.Exited.Before(cutoff) {
				delete(t.byExec, pr.ExecID)
				n++
				continue
			}
			kept = append(kept, pr)
		}
		if len(kept) == 0 {
			delete(t.byPID, pid)
		} else {
			t.byPID[pid] = kept
		}
	}
	return n
}

// Agents counts live agent processes per service (for the heartbeat).
func (t *Table) Agents() map[string]int {
	out := map[string]int{}
	for _, list := range t.byPID {
		for _, pr := range list {
			if pr.Agent() && pr.Exited.IsZero() {
				out[pr.Service]++
			}
		}
	}
	return out
}

func (t *Table) Len() int { return len(t.byExec) }
