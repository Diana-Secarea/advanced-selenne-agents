package ship

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type ev struct {
	Kind string `json:"kind"`
	N    int    `json:"n"`
}

func spool(t *testing.T, maxMB int) *Spool {
	t.Helper()
	s, err := OpenSpool(t.TempDir(), maxMB)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type fakeIngest struct {
	mu      sync.Mutex
	codes   []int // answers in turn, then 200
	got     [][]ev
	headers []http.Header
}

func (f *fakeIngest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headers = append(f.headers, r.Header.Clone())
	code := 200
	if len(f.codes) > 0 {
		code, f.codes = f.codes[0], f.codes[1:]
	}
	if code == 429 {
		w.Header().Set("Retry-After", "7")
	}
	if code != 200 {
		w.WriteHeader(code)
		io.WriteString(w, `{"error":"nope"}`)
		return
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	var batch []ev
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		var e ev
		json.Unmarshal(sc.Bytes(), &e)
		batch = append(batch, e)
	}
	f.got = append(f.got, batch)
	json.NewEncoder(w).Encode(map[string]int{"accepted": len(batch), "rejected": 0})
}

func sender(url string, s *Spool) *Sender {
	return &Sender{URL: url, Key: "sk_sel_test", UserAgent: "selenne-sensor/test", Client: http.DefaultClient,
		Spool: s, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		MinBackoff: time.Second, MaxBackoff: 30 * time.Second, AuthBackoff: time.Minute}
}

func TestSendsOldestFirstAndDeletes(t *testing.T) {
	ing := &fakeIngest{}
	srv := httptest.NewServer(ing)
	defer srv.Close()
	s := spool(t, 10)
	Put(s, []ev{{"exec", 1}, {"open", 2}})
	Put(s, []ev{{"connect", 3}})
	snd := sender(srv.URL, s)
	for {
		if _, more := snd.SendOne(context.Background()); !more {
			break
		}
	}
	if len(ing.got) != 2 || ing.got[0][0].N != 1 || ing.got[1][0].N != 3 || snd.Sent != 3 {
		t.Fatalf("got %v, sent %d", ing.got, snd.Sent)
	}
	h := ing.headers[0]
	if h.Get("Authorization") != "Bearer sk_sel_test" || h.Get("Content-Encoding") != "gzip" ||
		h.Get("Content-Type") != "application/x-ndjson" {
		t.Fatal(h)
	}
	if n, _ := s.Size(); n != 0 {
		t.Fatal("spool not emptied")
	}
}

func TestRetryRules(t *testing.T) {
	ing := &fakeIngest{codes: []int{503, 429, 401, 400}}
	srv := httptest.NewServer(ing)
	defer srv.Close()
	s := spool(t, 10)
	Put(s, []ev{{"exec", 1}})
	Put(s, []ev{{"exec", 2}})
	snd := sender(srv.URL, s)
	ctx := context.Background()

	if wait, _ := snd.SendOne(ctx); wait != time.Second { // 503: backoff starts
		t.Fatal("503 wait", wait)
	}
	if wait, _ := snd.SendOne(ctx); wait != 7*time.Second { // 429: Retry-After wins
		t.Fatal("429 wait", wait)
	}
	if wait, _ := snd.SendOne(ctx); wait != time.Minute { // 401: kept, slow retry
		t.Fatal("401 wait", wait)
	}
	if n, _ := s.Size(); n != 2 {
		t.Fatal("a retryable failure lost a batch")
	}
	snd.SendOne(ctx) // 400: that batch is dropped
	if n, _ := s.Size(); n != 1 || snd.DroppedBad != 1 {
		t.Fatal("400 must drop the batch")
	}
	snd.SendOne(ctx) // 200
	if len(ing.got) != 1 || ing.got[0][0].N != 2 {
		t.Fatal(ing.got)
	}
}

func TestUnreachableKeepsBatches(t *testing.T) {
	s := spool(t, 10)
	Put(s, []ev{{"exec", 1}})
	snd := sender("http://127.0.0.1:1", s)
	if wait, more := snd.SendOne(context.Background()); !more || wait == 0 {
		t.Fatal(wait, more)
	}
	if n, _ := s.Size(); n != 1 {
		t.Fatal("batch lost while unreachable")
	}
}

func TestSpoolCapDropsOldest(t *testing.T) {
	s := spool(t, 1) // 1 MB
	big := make([]ev, 0, 60000)
	for i := 0; i < 60000; i++ {
		big = append(big, ev{strings.Repeat("x", 40) + string(rune('a'+i%26)), i})
	}
	for i := 0; i < 6; i++ {
		if err := Put(s, big); err != nil {
			t.Fatal(err)
		}
	}
	n, bytes := s.Size()
	if bytes > 1<<20 && n > 1 || s.Dropped == 0 {
		t.Fatalf("spool %d files %d bytes, dropped %d", n, bytes, s.Dropped)
	}
	// the newest batch always survives
	names, _ := filepath.Glob(filepath.Join(s.dir, "*"+ext))
	if !strings.HasSuffix(names[len(names)-1], "0000000000000006"+ext) {
		t.Fatal(names)
	}
}

func TestSpoolSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenSpool(dir, 10)
	Put(s, []ev{{"exec", 1}})
	s2, _ := OpenSpool(dir, 10)
	Put(s2, []ev{{"exec", 2}})
	names, _ := filepath.Glob(filepath.Join(dir, "*"+ext))
	if len(names) != 2 || !strings.HasSuffix(names[1], "0000000000000002"+ext) {
		t.Fatal("sequence restarted and could overwrite:", names)
	}
	os.WriteFile(filepath.Join(dir, "x"+ext+".tmp"), []byte("half"), 0o600) // crash mid-write
	if n, _ := s2.Size(); n != 2 {
		t.Fatal("a half-written batch counts")
	}
}
