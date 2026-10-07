// Package ship gets host events to Selenne: batches are written to a disk
// spool first (so nothing is lost while Selenne is unreachable or the sensor
// restarts) and a sender posts them, oldest first, deleting each once
// ingest has stored it.
package ship

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const ext = ".ndjson.gz"

type Spool struct {
	dir      string
	maxBytes int64
	mu       sync.Mutex
	seq      uint64
	notify   chan struct{}
	Dropped  int64 // batches deleted because the spool was full
}

func OpenSpool(dir string, maxMB int) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Spool{dir: dir, maxBytes: int64(maxMB) << 20, notify: make(chan struct{}, 1)}
	for _, name := range s.list() {
		if n, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(name), ext), 10, 64); err == nil && n > s.seq {
			s.seq = n
		}
	}
	return s, nil
}

func (s *Spool) list() []string {
	names, _ := filepath.Glob(filepath.Join(s.dir, "*"+ext))
	sort.Strings(names) // zero-padded sequence numbers: oldest first
	return names
}

// Put writes one batch (gzipped NDJSON, the body ingest takes as is).
func Put[T any](s *Spool, events []T) error {
	if len(events) == 0 {
		return nil
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	enc.SetEscapeHTML(false)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return s.write(buf.Bytes())
}

func (s *Spool) write(body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	name := filepath.Join(s.dir, fmt.Sprintf("%016d%s", s.seq, ext))
	tmp := name + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil { // on disk before the position moves past it
		f.Close()
		return err
	}
	f.Close()
	if err := os.Rename(tmp, name); err != nil {
		return err
	}
	s.trim()
	select {
	case s.notify <- struct{}{}:
	default:
	}
	return nil
}

// trim deletes the oldest batches while the spool is over its cap: after a
// long outage the newest activity is the most useful, and the disk is the
// customer's.
func (s *Spool) trim() {
	if s.maxBytes <= 0 {
		return
	}
	names := s.list()
	var total int64
	sizes := make([]int64, len(names))
	for i, n := range names {
		if fi, err := os.Stat(n); err == nil {
			sizes[i] = fi.Size()
			total += sizes[i]
		}
	}
	for i := 0; total > s.maxBytes && i < len(names)-1; i++ {
		if os.Remove(names[i]) == nil {
			total -= sizes[i]
			s.Dropped++
		}
	}
}

// Oldest returns the next batch to send.
func (s *Spool) Oldest() (string, []byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.list() {
		body, err := os.ReadFile(n)
		if err == nil {
			return n, body, true
		}
	}
	return "", nil, false
}

func (s *Spool) Remove(name string) error { return os.Remove(name) }

// Size is the number of batches waiting and their total bytes.
func (s *Spool) Size() (int, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var total int64
	names := s.list()
	for _, n := range names {
		if fi, err := os.Stat(n); err == nil {
			total += fi.Size()
		}
	}
	return len(names), total
}

// Notify is signalled whenever a batch is added.
func (s *Spool) Notify() <-chan struct{} { return s.notify }
