package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/config"
)

func TestDryRunPrintsWhatWouldBeSent(t *testing.T) {
	cfg := config.Default()
	cfg.Host = "dev-box"
	var out bytes.Buffer
	if err := dryRun(cfg, []string{"../../testdata/spike.jsonl"}, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 16 {
		t.Fatalf("%d events:\n%s", len(lines), out.String())
	}
	var first map[string]any
	json.Unmarshal([]byte(lines[0]), &first)
	if first["kind"] != "exec" || first["host"] != "dev-box" || first["service_name"] != "spike-agent" {
		t.Fatal(first)
	}
	if err := dryRun(cfg, nil, &out); err == nil {
		t.Fatal("no files accepted")
	}
}
