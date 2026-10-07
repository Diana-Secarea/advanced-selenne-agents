// Package tetragon reads Tetragon's JSON export: one event per line, only the
// fields the sensor uses. Tetragon's own Go API module is large and pulls in
// half of Cilium, so these are small local mirrors of its JSON shape.
package tetragon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type EnvVar struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type Container struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Pod struct {
	Namespace string     `json:"namespace"`
	Name      string     `json:"name"`
	Container *Container `json:"container"`
}

type Process struct {
	ExecID       string    `json:"exec_id"`
	PID          uint32    `json:"pid"`
	UID          *uint32   `json:"uid"`
	CWD          string    `json:"cwd"`
	Binary       string    `json:"binary"`
	Arguments    string    `json:"arguments"`
	Flags        string    `json:"flags"`
	StartTime    time.Time `json:"start_time"`
	ParentExecID string    `json:"parent_exec_id"`
	Docker       string    `json:"docker"` // container id, truncated to 31 chars
	Pod          *Pod      `json:"pod"`
	Env          []EnvVar  `json:"environment_variables"`
}

// Known reports whether Tetragon could enrich the process. Kprobe events
// for a process it never saw start carry only pid + "flags": "unknown".
func (p *Process) Known() bool { return p.ExecID != "" }

// ContainerID is the best container id Tetragon gave: the pod's (full) one
// on Kubernetes, else the truncated docker one.
func (p *Process) ContainerID() string {
	if p.Pod != nil && p.Pod.Container != nil && p.Pod.Container.ID != "" {
		return strings.TrimPrefix(p.Pod.Container.ID, "containerd://")
	}
	return p.Docker
}

func (p *Process) EnvValue(key string) string {
	for _, e := range p.Env {
		if e.Key == key {
			return e.Value
		}
	}
	return ""
}

type FileArg struct {
	Path       string `json:"path"`
	Flags      string `json:"flags"`
	Permission string `json:"permission"`
}

type SockArg struct {
	Family   string `json:"family"`
	Type     string `json:"type"`
	Protocol string `json:"protocol"`
	Saddr    string `json:"saddr"`
	Daddr    string `json:"daddr"`
	Sport    uint32 `json:"sport"`
	Dport    uint32 `json:"dport"`
	State    string `json:"state"`
}

type KprobeArg struct {
	FileArg *FileArg `json:"file_arg"`
	SockArg *SockArg `json:"sock_arg"`
}

type ProcessExec struct {
	Process Process  `json:"process"`
	Parent  *Process `json:"parent"`
}

type ProcessExit struct {
	Process Process  `json:"process"`
	Parent  *Process `json:"parent"`
	Signal  string   `json:"signal"`
	Status  uint32   `json:"status"`
}

type ProcessKprobe struct {
	Process      Process     `json:"process"`
	Parent       *Process    `json:"parent"`
	FunctionName string      `json:"function_name"`
	Args         []KprobeArg `json:"args"`
	PolicyName   string      `json:"policy_name"`
}

// Event is one line of the export. Exactly one of Exec, Exit, Kprobe is set
// for the kinds the sensor handles; anything else leaves all three nil.
type Event struct {
	Exec   *ProcessExec   `json:"process_exec"`
	Exit   *ProcessExit   `json:"process_exit"`
	Kprobe *ProcessKprobe `json:"process_kprobe"`
	Node   string         `json:"node_name"`
	Time   time.Time      `json:"time"`

	Raw    []byte `json:"-"` // the line as read, for a stable event id
	Offset int64  `json:"-"` // byte offset of the line in its file
}

func Parse(line []byte) (Event, error) {
	var ev Event
	if err := json.Unmarshal(line, &ev); err != nil {
		return ev, err
	}
	ev.Raw = line
	return ev, nil
}

// Process returns the event's process, whichever kind it is.
func (e *Event) Process() *Process {
	switch {
	case e.Exec != nil:
		return &e.Exec.Process
	case e.Exit != nil:
		return &e.Exit.Process
	case e.Kprobe != nil:
		return &e.Kprobe.Process
	}
	return nil
}

// ExecIDPID decodes the pid out of an exec id: base64("node:ktime:pid").
// It works even when Tetragon could not resolve the parent (ktime 0), which
// is how a child is tied to its parent on hosts like WSL2.
func ExecIDPID(execID string) (uint32, bool) {
	raw, err := base64.StdEncoding.DecodeString(execID)
	if err != nil {
		return 0, false
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return 0, false
	}
	pid, err := strconv.ParseUint(s[i+1:], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(pid), true
}

// SplitArgs splits Tetragon's single-string arguments the way a shell
// would: spaces separate, double or single quotes group, backslash escapes.
func SplitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inArg, quote := false, byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && quote != '\'' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			inArg = true
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote, inArg = c, true
		case c == ' ' || c == '\t':
			if inArg {
				out = append(out, cur.String())
				cur.Reset()
				inArg = false
			}
		default:
			cur.WriteByte(c)
			inArg = true
		}
	}
	if inArg {
		out = append(out, cur.String())
	}
	return out
}

func (e Event) String() string {
	p := e.Process()
	if p == nil {
		return "event(other)"
	}
	kind := "exec"
	if e.Exit != nil {
		kind = "exit"
	} else if e.Kprobe != nil {
		kind = e.Kprobe.FunctionName
	}
	return fmt.Sprintf("%s pid=%d %s", kind, p.PID, p.Binary)
}
