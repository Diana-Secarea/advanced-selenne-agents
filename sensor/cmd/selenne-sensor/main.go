// selenne-sensor ships what Tetragon sees AI agents doing to Selenne.
//
//	selenne-sensor run      [-config sensor.yaml]   follow Tetragon's export and ship
//	selenne-sensor policies [-config sensor.yaml] -out DIR
//	                                                 write the Tetragon policies
//	selenne-sensor dry-run  [-config sensor.yaml] FILE…
//	                                                 print what would be sent for
//	                                                 these Tetragon export files
//	selenne-sensor version
//
// The ingestion key comes from $SELENNE_SENSOR_KEY (ingest.key_env).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/config"
	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/pipeline"
	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/policy"
	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/ship"
	"github.com/Diana-Secarea/advanced-selenne-agents/sensor/internal/tetragon"
)

var version = "dev" // -ldflags "-X main.version=…"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("app", "selenne-sensor")
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: selenne-sensor run|policies|dry-run|version [-config sensor.yaml]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	cfgPath := fs.String("config", os.Getenv("SELENNE_SENSOR_CONFIG"), "sensor.yaml (defaults when empty)")
	out := fs.String("out", "", "policies: directory to write into")
	fs.Parse(os.Args[2:])

	if os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "policies":
		if *out == "" {
			log.Error("policies needs -out DIR")
			os.Exit(2)
		}
		written, err := policy.Write(cfg, *out)
		if err != nil {
			log.Error("policies", "err", err)
			os.Exit(1)
		}
		log.Info("policies written", "files", written)
	case "dry-run":
		if err := dryRun(cfg, fs.Args(), os.Stdout); err != nil {
			log.Error("dry-run", "err", err)
			os.Exit(1)
		}
	case "run":
		if err := run(cfg, log); err != nil {
			log.Error("sensor stopped", "err", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
}

func run(cfg config.Config, log *slog.Logger) error {
	key, err := cfg.Key()
	if err != nil {
		return err
	}
	spool, err := ship.OpenSpool(filepath.Join(cfg.StateDir, "spool"), cfg.Shipping.SpoolMaxMB)
	if err != nil {
		return err
	}
	posFile := filepath.Join(cfg.StateDir, "position.json")
	pos := loadPosition(posFile)

	p := pipeline.New(cfg, version)
	learned := replay(p, cfg.Tetragon.ExportFile, pos)
	tail, err := tetragon.OpenTailer(cfg.Tetragon.ExportFile, pos)
	if err != nil {
		return err
	}
	defer tail.Close()
	log.Info("sensor running", "version", version, "host", cfg.Host, "export", cfg.Tetragon.ExportFile,
		"ingest", cfg.Ingest.URL, "resume", tail.Position(), "replayed", learned)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	sender := &ship.Sender{URL: cfg.Ingest.URL, Key: key, UserAgent: "selenne-sensor/" + version,
		Client: &http.Client{Timeout: cfg.Shipping.Timeout}, Spool: spool,
		Log: log.With("part", "sender"), MinBackoff: time.Second, MaxBackoff: time.Minute,
		AuthBackoff: 5 * time.Minute}
	sendCtx, stopSending := context.WithCancel(context.Background())
	defer stopSending()
	sent := make(chan struct{})
	go func() { sender.Run(sendCtx); close(sent) }()

	flush := time.NewTicker(cfg.Shipping.FlushInterval)
	defer flush.Stop()
	beat := time.NewTicker(cfg.Shipping.Heartbeat)
	defer beat.Stop()

	ship := func(events []pipeline.HostEvent) error {
		for len(events) > 0 {
			n := min(len(events), cfg.Shipping.BatchMax)
			if err := ship.Put(spool, events[:n]); err != nil {
				return err
			}
			events = events[n:]
		}
		return nil
	}
	save := func() {
		at := tail.Position()
		if held, ok := p.Pending(); ok {
			at = held
		}
		if err := savePosition(posFile, at); err != nil {
			log.Warn("saving position", "err", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			// whatever is held goes now; the position then covers all of it
			err := ship(p.Flush())
			save()
			drain(sender, sendCtx, spool, stopSending, sent)
			log.Info("sensor stopped", "stats", p.Stats, "sender", sender.String())
			return err
		case <-beat.C:
			if err := ship([]pipeline.HostEvent{heartbeat(cfg, p, spool, sender)}); err != nil {
				log.Warn("heartbeat", "err", err)
			}
		case <-flush.C:
			if err := readAvailable(tail, p, log, 50000); err != nil {
				log.Warn("reading export", "err", err)
			}
			if err := ship(p.Release(time.Now())); err != nil {
				return fmt.Errorf("spool: %w", err) // the disk is gone: let the supervisor restart us
			}
			save()
		}
	}
}

// readAvailable reads up to max lines that Tetragon has written so far.
func readAvailable(t *tetragon.Tailer, p *pipeline.Pipeline, log *slog.Logger, max int) error {
	for i := 0; i < max; i++ {
		line, _, ok, err := t.Next()
		if err != nil || !ok {
			return err
		}
		at := t.Position()
		at.Offset -= int64(len(line)) + 1 // where this line starts
		ev, err := tetragon.Parse(line)
		if err != nil {
			p.Stats.Unparsed++
			continue
		}
		p.Add(ev, at)
	}
	return nil
}

// replay feeds the history before pos into the process table, so a restart
// still knows which running processes are agents. Nothing is shipped.
func replay(p *pipeline.Pipeline, export string, pos tetragon.Position) int {
	if pos.Inode == 0 {
		return 0
	}
	n := 0
	learn := func(line []byte) {
		if ev, err := tetragon.Parse(line); err == nil {
			p.Learn(ev)
			n++
		}
	}
	for _, name := range append(tetragon.Rotated(export), export) {
		if fi, err := os.Stat(name); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Ino == pos.Inode {
				tetragon.ForEachLine(name, pos.Offset, learn)
				return n
			}
		}
		tetragon.ForEachLine(name, -1, learn)
	}
	return n
}

func heartbeat(cfg config.Config, p *pipeline.Pipeline, spool *ship.Spool, s *ship.Sender) pipeline.HostEvent {
	now := time.Now()
	batches, bytes := spool.Size()
	return pipeline.HostEvent{Kind: "sensor.heartbeat", Host: cfg.Host, PID: uint32(os.Getpid()),
		TsUnixNano: now.UnixNano(), EventID: fmt.Sprintf("hb:%s:%d", cfg.Host, now.UnixNano()),
		SensorVersion: version, Stats: map[string]any{
			"agents": p.Procs().Agents(), "processes_tracked": p.Procs().Len(),
			"read": p.Stats.Read, "released": p.Stats.Released, "dropped": p.Stats.Dropped,
			"unparsed": p.Stats.Unparsed, "held": p.Held(),
			"spool_batches": batches, "spool_bytes": bytes, "spool_dropped": spool.Dropped,
			"sent": s.Sent, "rejected": s.Rejected, "dropped_bad": s.DroppedBad,
		}}
}

// drain gives the sender a few seconds to post what is spooled; anything
// left stays on disk for the next start.
func drain(s *ship.Sender, ctx context.Context, spool *ship.Spool, stop context.CancelFunc, done <-chan struct{}) {
	deadline := time.After(5 * time.Second)
	for {
		if n, _ := spool.Size(); n == 0 {
			break
		}
		select {
		case <-deadline:
			stop()
			<-done
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	stop()
	<-done
}

func loadPosition(name string) tetragon.Position {
	var pos tetragon.Position
	raw, err := os.ReadFile(name)
	if err == nil {
		json.Unmarshal(raw, &pos)
	}
	return pos
}

func savePosition(name string, pos tetragon.Position) error {
	raw, _ := json.Marshal(pos)
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			os.MkdirAll(filepath.Dir(name), 0o700)
			err = os.WriteFile(tmp, raw, 0o600)
		}
		if err != nil {
			return err
		}
	}
	return os.Rename(tmp, name)
}

// dryRun pushes whole export files through the pipeline and prints the host
// events, one JSON per line — exactly the body run would send. Nothing is
// sent and no key is needed.
func dryRun(cfg config.Config, files []string, w io.Writer) error {
	if len(files) == 0 {
		return errors.New("dry-run needs one or more Tetragon export files")
	}
	p := pipeline.New(cfg, version)
	for _, name := range files {
		var off int64
		err := tetragon.ForEachLine(name, -1, func(line []byte) {
			if ev, err := tetragon.Parse(slices.Clone(line)); err == nil {
				p.Add(ev, tetragon.Position{Path: name, Offset: off})
			}
			off += int64(len(line)) + 1
		})
		if err != nil {
			return err
		}
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, e := range p.Flush() {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}
