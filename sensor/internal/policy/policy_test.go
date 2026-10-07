package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/config"
)

type tracingPolicy struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Kprobes []struct {
			Call      string `yaml:"call"`
			Selectors []struct {
				MatchArgs []struct {
					Operator string   `yaml:"operator"`
					Values   []string `yaml:"values"`
				} `yaml:"matchArgs"`
			} `yaml:"selectors"`
		} `yaml:"kprobes"`
	} `yaml:"spec"`
}

func parse(t *testing.T, body string) tracingPolicy {
	t.Helper()
	var p tracingPolicy
	if err := yaml.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("not valid YAML: %v\n%s", err, body)
	}
	return p
}

func TestFilesPolicy(t *testing.T) {
	f := config.Default().Files
	f.SkipPrefixes = append(f.SkipPrefixes, `/odd "quoted" path/`)
	p := parse(t, Files(f))
	if p.Kind != "TracingPolicy" || p.Metadata.Name != "selenne-files" || p.Spec.Kprobes[0].Call != "security_file_open" {
		t.Fatal(p)
	}
	sel := p.Spec.Kprobes[0].Selectors
	if len(sel) != 2 {
		t.Fatalf("want a sensitive selector and an activity selector, got %d", len(sel))
	}
	if sel[0].MatchArgs[0].Operator != "Postfix" || len(sel[0].MatchArgs[0].Values) != len(f.Sensitive) {
		t.Fatal("sensitive selector", sel[0])
	}
	ops := []string{sel[1].MatchArgs[0].Operator, sel[1].MatchArgs[1].Operator}
	if ops[0] != "NotPrefix" || ops[1] != "NotPostfix" {
		t.Fatal(ops)
	}
	if last := sel[1].MatchArgs[0].Values; last[len(last)-1] != `/odd "quoted" path/` {
		t.Fatal("quoting", last)
	}
}

func TestWriteHonoursFilesDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	if got, err := Write(cfg, dir); err != nil || len(got) != 3 {
		t.Fatal(got, err)
	}
	for _, name := range []string{"selenne-connect.yaml", "selenne-listen.yaml"} {
		raw, _ := os.ReadFile(filepath.Join(dir, name))
		if p := parse(t, string(raw)); !strings.HasPrefix(p.Metadata.Name, "selenne-") {
			t.Fatal(name, p)
		}
	}
	cfg.Files.Enabled = false
	Write(cfg, dir)
	if _, err := os.Stat(filepath.Join(dir, "selenne-files.yaml")); !os.IsNotExist(err) {
		t.Fatal("file policy left behind after files were disabled")
	}
}
