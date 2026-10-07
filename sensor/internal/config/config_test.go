package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// sensor.example.yaml documents the defaults; it must stay equal to them.
func TestExampleFileIsTheDefaults(t *testing.T) {
	t.Setenv("SELENNE_SENSOR_INGEST_URL", "")
	got, err := Load("../../sensor.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := Default()
	want.Network.PortLabels = map[int]string{} // the example spells out the empty ones
	want.Agents.Match = []AgentRule{}
	if err := want.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sensor.example.yaml differs from Default():\n got  %+v\n want %+v", got, want)
	}
}

func TestOverridesAndErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "s.yaml")
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	c, err := Load(write("ingest: {url: 'http://ingest:4318/'}\nnetwork: {local: false, port_labels: {7000: billing-api}}\nshipping: {hold: 3s}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Ingest.URL != "http://ingest:4318" || c.Network.Local || !c.Network.Public ||
		c.Network.PortLabels[7000] != "billing-api" || c.Shipping.Hold.Seconds() != 3 {
		t.Fatalf("%+v", c)
	}
	for _, bad := range []string{
		"ingest: {url: ingest.selenne.app}",
		"agents: {match: [{binary: x}]}",
		"agents: {match: [{service: a}]}",
		"agents: {match: [{service: a, binary: '('}]}",
	} {
		if _, err := Load(write(bad)); err == nil {
			t.Errorf("accepted: %s", bad)
		}
	}
	t.Setenv("SELENNE_SENSOR_KEY", "")
	if _, err := c.Key(); err == nil {
		t.Error("missing key accepted")
	}
}

func TestHostAndURLFromTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	old := HostNameFile
	HostNameFile = filepath.Join(dir, "hostname")
	defer func() { HostNameFile = old }()
	os.WriteFile(HostNameFile, []byte("selenne-prod\n"), 0o644)
	t.Setenv("NODE_NAME", "")
	t.Setenv("SELENNE_SENSOR_INGEST_URL", "http://ingest:4318/")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "selenne-prod" || c.Ingest.URL != "http://ingest:4318" {
		t.Fatalf("host %q url %q", c.Host, c.Ingest.URL)
	}
	t.Setenv("NODE_NAME", "node-7") // NODE_NAME wins (Kubernetes downward API)
	if c, _ := Load(""); c.Host != "node-7" {
		t.Fatal(c.Host)
	}
}
