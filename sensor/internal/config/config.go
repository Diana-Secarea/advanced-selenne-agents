// Package config is sensor.yaml: every choice a customer may want to change,
// with defaults that work untouched. The ingestion key never lives in the
// file — it comes from the environment (SELENNE_SENSOR_KEY by default).
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Ingest   Ingest   `yaml:"ingest"`
	Host     string   `yaml:"host"` // reported host name; default: NODE_NAME, the host's /etc/hostname mounted at HostNameFile, then the hostname
	Tetragon Tetragon `yaml:"tetragon"`
	StateDir string   `yaml:"state_dir"` // position + spool
	Agents   Agents   `yaml:"agents"`
	Network  Network  `yaml:"network"`
	Files    Files    `yaml:"files"`
	Shipping Shipping `yaml:"shipping"`
}

type Ingest struct {
	URL    string `yaml:"url"`     // base URL; /v1/host-events is appended
	KeyEnv string `yaml:"key_env"` // environment variable holding the sk_sel_ key
}

type Tetragon struct {
	ExportFile string `yaml:"export_file"`
}

// Agents decides which processes are agents. Zero-config: any process
// started with OTEL_SERVICE_NAME (or service.name in OTEL_RESOURCE_ATTRIBUTES)
// is one, named after that service — except IgnoreServices, which set the
// variable for their own tracing. Match adds agents that do not use OTel.
// Children of an agent are always part of it.
type Agents struct {
	ZeroConfig     bool        `yaml:"zero_config"`
	IgnoreServices []string    `yaml:"ignore_services"`
	Match          []AgentRule `yaml:"match"`
}

type AgentRule struct {
	Service string `yaml:"service"` // the name it is reported under
	Binary  string `yaml:"binary"`  // regexp on the executable path
	Args    string `yaml:"args"`    // regexp on the command line (optional)

	binary, args *regexp.Regexp
}

func (r *AgentRule) Matches(binary, args string) bool {
	if r.binary != nil && !r.binary.MatchString(binary) {
		return false
	}
	if r.args != nil && !r.args.MatchString(args) {
		return false
	}
	return r.binary != nil || r.args != nil
}

// Network: which of an agent's connections are recorded, by scope, and
// extra names for ports (on top of the built-in list and live listeners).
type Network struct {
	Local      bool           `yaml:"local"`   // loopback
	Private    bool           `yaml:"private"` // RFC 1918, link-local, CGNAT, Docker networks
	Public     bool           `yaml:"public"`
	PortLabels map[int]string `yaml:"port_labels"`
}

// Files: the open() events Tetragon sends at all are decided in the kernel
// (the rendered policy): every file outside SkipPrefixes / SkipSuffixes,
// plus Sensitive files wherever they are. The kernel only matches prefixes
// and suffixes, so the shipper then drops what needs more than that: paths
// containing SkipContains, folders, and versioned shared libraries.
// Sensitive files are never dropped.
type Files struct {
	Enabled         bool     `yaml:"enabled"`
	SkipPrefixes    []string `yaml:"skip_prefixes"`
	SkipSuffixes    []string `yaml:"skip_suffixes"`
	SkipContains    []string `yaml:"skip_contains"`
	SkipDirectories bool     `yaml:"skip_directories"` // a program listing a folder, e.g. Python importing
	Sensitive       []string `yaml:"sensitive"`        // path suffixes, always recorded
}

type Shipping struct {
	BatchMax      int           `yaml:"batch_max"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	Hold          time.Duration `yaml:"hold"`     // the export is flushed late and out of order: wait this long to re-sort
	MaxWait       time.Duration `yaml:"max_wait"` // an event whose process start has not been read yet waits up to this
	SpoolMaxMB    int           `yaml:"spool_max_mb"`
	Heartbeat     time.Duration `yaml:"heartbeat"`
	Timeout       time.Duration `yaml:"timeout"`
}

// HostNameFile is where a container sees the host's /etc/hostname (mounted
// read-only): inside a container the hostname is the container id.
var HostNameFile = "/etc/host-hostname"

func Default() Config {
	return Config{
		Ingest:   Ingest{URL: "https://ingest.selenne.app", KeyEnv: "SELENNE_SENSOR_KEY"},
		Tetragon: Tetragon{ExportFile: "/var/run/tetragon/events.log"},
		StateDir: "/var/lib/selenne-sensor",
		Agents: Agents{
			ZeroConfig: true,
			// infrastructure that sets OTEL_SERVICE_NAME for its own tracing;
			// a trailing * matches a prefix (containerd names each shim
			// containerd-shim-<container id>)
			IgnoreServices: []string{
				"dockerd", "docker-proxy", "buildkitd", "containerd*", // Docker, containerd + its shims
				"crio", "conmon*", "podman*", "cri-dockerd", // CRI-O, Podman
				"kubelet", "kube-proxy", "k3s*", "rke2*", // Kubernetes node components
				"tetragon", "selenne-sensor", // the sensor itself
			},
		},
		Network: Network{Local: true, Private: true, Public: true},
		Files: Files{
			Enabled: true,
			SkipPrefixes: []string{"/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/proc/", "/sys/",
				"/dev/", "/run/", "/var/lib/docker/", "/var/lib/containerd/", "/opt/conda/pkgs/",
				// lookups every program makes (users, DNS, TLS roots, time zone, loader)
				"/etc/ld.so", "/etc/localtime", "/etc/passwd", "/etc/group", "/etc/nsswitch.conf",
				"/etc/gai.conf", "/etc/hosts", "/etc/resolv.conf", "/etc/host.conf", "/etc/ssl/",
				"/etc/ca-certificates", "/etc/pki/", "/etc/mime.types",
				// databases' own data and logs: busy, and never an agent's doing
				"/var/lib/postgresql/", "/var/lib/mysql/", "/var/lib/redis/", "/var/log/"},
			SkipSuffixes: []string{".py", ".pyc", ".so", ".pth", ".dist-info/METADATA", ".mo", ".js", ".node"},
			// libraries and caches inside a project or a virtualenv
			SkipContains:    []string{"/site-packages/", "/dist-packages/", "/node_modules/", "/__pycache__/", "/.cache/"},
			SkipDirectories: true,
			Sensitive: []string{"/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/id_ecdsa", "/.ssh/authorized_keys",
				"/.aws/credentials", "/.config/gcloud/credentials.db", "/.kube/config", "/.docker/config.json",
				"/.git-credentials", "/.netrc", "/.env", "/etc/shadow", "/etc/sudoers"},
		},
		Shipping: Shipping{BatchMax: 1000, FlushInterval: time.Second, Hold: 10 * time.Second, MaxWait: time.Minute,
			SpoolMaxMB: 100, Heartbeat: 30 * time.Second, Timeout: 15 * time.Second},
	}
}

// Load reads path over the defaults; an empty path means defaults only.
func Load(path string) (Config, error) {
	c := Default()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return c, err
		}
		if err := yaml.Unmarshal(raw, &c); err != nil {
			return c, fmt.Errorf("%s: %w", path, err)
		}
	}
	return c, c.Validate()
}

// Validate fills derived defaults (host) and checks the settings.
func (c *Config) Validate() error {
	if c.Host == "" {
		c.Host = os.Getenv("NODE_NAME")
	}
	if c.Host == "" {
		if raw, err := os.ReadFile(HostNameFile); err == nil {
			c.Host = strings.TrimSpace(string(raw))
		}
	}
	if c.Host == "" {
		c.Host, _ = os.Hostname()
	}
	// one compose file for customers and for a stack next to ingest: the
	// URL can come from the environment
	if u := strings.TrimSpace(os.Getenv("SELENNE_SENSOR_INGEST_URL")); u != "" {
		c.Ingest.URL = u
	}
	c.Ingest.URL = strings.TrimRight(c.Ingest.URL, "/")
	if !strings.HasPrefix(c.Ingest.URL, "http://") && !strings.HasPrefix(c.Ingest.URL, "https://") {
		return fmt.Errorf("ingest.url must be http(s)://…, got %q", c.Ingest.URL)
	}
	for i := range c.Agents.Match {
		r := &c.Agents.Match[i]
		if r.Service == "" {
			return fmt.Errorf("agents.match[%d]: service is required", i)
		}
		var err error
		if r.Binary != "" {
			if r.binary, err = regexp.Compile(r.Binary); err != nil {
				return fmt.Errorf("agents.match[%d].binary: %w", i, err)
			}
		}
		if r.Args != "" {
			if r.args, err = regexp.Compile(r.Args); err != nil {
				return fmt.Errorf("agents.match[%d].args: %w", i, err)
			}
		}
		if r.binary == nil && r.args == nil {
			return fmt.Errorf("agents.match[%d]: needs binary or args", i)
		}
	}
	if c.Shipping.BatchMax <= 0 || c.Shipping.FlushInterval <= 0 || c.Shipping.Hold < 0 {
		return fmt.Errorf("shipping: batch_max and flush_interval must be positive")
	}
	return nil
}

// Key returns the ingestion key from the environment.
func (c *Config) Key() (string, error) {
	k := strings.TrimSpace(os.Getenv(c.Ingest.KeyEnv))
	if k == "" {
		return "", fmt.Errorf("no ingestion key: set %s (a sk_sel_… key from your Selenne profile)", c.Ingest.KeyEnv)
	}
	return k, nil
}
