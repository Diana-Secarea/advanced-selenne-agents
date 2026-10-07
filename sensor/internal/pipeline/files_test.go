package pipeline

import (
	"testing"

	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/config"
	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/tetragon"
)

// What the CVE agent's run looked like before these filters: folder listings
// while importing, its virtualenv's libraries, next to the files that matter.
func TestFileFilters(t *testing.T) {
	p := New(config.Default(), "test")
	venv := "/home/sek/wazuh/wazuh-monorepo/services/ai-engine/venv/lib/python3.13/site-packages"
	cases := []struct {
		path, perm string
		want       bool
	}{
		{"/var/ossec/ruleset/rules/0095-sshd_rules.xml", "-rw-r-----", true}, // the agent's real work
		{"/home/sek/wazuh/wazuh-monorepo/services/ai-engine/venv/pyvenv.cfg", "-rw-r--r--", true},
		{"/home/sek/wazuh/wazuh-monorepo/services/ai-engine/rag_core", "drwxr-xr-x", false}, // import
		{venv + "/psycopg2_binary.libs/libssl-81ffa89e.so.3", "-rwxr-xr-x", false},
		{venv + "/certifi/cacert.pem", "-rw-r--r--", false},
		{"/usr/lib/x86_64-linux-gnu/libpq.so.5.17", "-rw-r--r--", false},
		{"/app/node_modules/x/package.json", "-rw-r--r--", false},
		{"/tmp/spike-home-x/.ssh/id_rsa", "-rw-------", true},
		{venv + "/leaked/.env", "-rw-r--r--", true}, // sensitive beats every skip
		{"/home/u/.ssh/id_rsa", "drwx------", true},
	}
	for _, c := range cases {
		if got := p.fileWanted(&tetragon.FileArg{Path: c.path, Permission: c.perm}); got != c.want {
			t.Errorf("fileWanted(%s, %s) = %v, want %v", c.path, c.perm, got, c.want)
		}
	}
}
