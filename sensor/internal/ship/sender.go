package ship

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// Sender posts spooled batches to POST {url}/v1/host-events.
//
//	2xx                 stored: the batch is deleted
//	429, 5xx, no answer retried with backoff, honouring Retry-After
//	401, 402            kept and retried slowly: the key or the plan needs
//	                    fixing, and the data is still worth having once it is
//	other 4xx           the batch itself is bad and never will be good: dropped
type Sender struct {
	URL       string
	Key       string
	UserAgent string
	Client    *http.Client
	Spool     *Spool
	Log       *slog.Logger

	MinBackoff, MaxBackoff, AuthBackoff time.Duration

	Sent, Rejected, DroppedBad int64
	backoff                    time.Duration
}

type ingestReply struct {
	Accepted int    `json:"accepted"`
	Rejected int    `json:"rejected"`
	Error    string `json:"error"`
}

// SendOne posts the oldest batch. It returns how long to wait before the
// next attempt (0: go on), and false when the spool is empty.
func (s *Sender) SendOne(ctx context.Context) (time.Duration, bool) {
	name, body, ok := s.Spool.Oldest()
	if !ok {
		return 0, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL+"/v1/host-events", bytes.NewReader(body))
	if err != nil {
		s.Log.Error("bad ingest url", "err", err)
		return s.AuthBackoff, true
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+s.Key)
	req.Header.Set("User-Agent", s.UserAgent)
	resp, err := s.Client.Do(req)
	if err != nil {
		return s.retry("ingest unreachable", 0, "err", err), true
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var reply ingestReply
	_ = json.Unmarshal(raw, &reply)
	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		s.Spool.Remove(name)
		s.backoff = 0
		s.Sent += int64(reply.Accepted)
		if reply.Rejected > 0 {
			s.Rejected += int64(reply.Rejected)
			s.Log.Warn("ingest rejected events", "rejected", reply.Rejected, "error", reply.Error)
		}
		return 0, true
	case code == 429 || code >= 500:
		return s.retry("ingest busy", retryAfter(resp), "status", code), true
	case code == 401 || code == 402:
		s.Log.Error("ingest refused the key — check the sk_sel_ key and that Selenne Agents is enabled; keeping events",
			"status", code, "error", reply.Error)
		return s.AuthBackoff, true
	default:
		s.Spool.Remove(name)
		s.DroppedBad++
		s.Log.Error("ingest refused a batch; dropped it", "status", code, "error", reply.Error)
		return 0, true
	}
}

func (s *Sender) retry(msg string, after time.Duration, args ...any) time.Duration {
	if s.backoff == 0 {
		s.backoff = s.MinBackoff
	} else {
		s.backoff = min(s.backoff*2, s.MaxBackoff)
	}
	wait := max(s.backoff, after)
	s.Log.Warn(msg+", retrying", append(args, "in", wait.String())...)
	return wait
}

func retryAfter(resp *http.Response) time.Duration {
	if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}

// Run sends until ctx ends, waking when the spool gets a batch.
func (s *Sender) Run(ctx context.Context) {
	for {
		wait, more := s.SendOne(ctx)
		if more && wait == 0 {
			continue
		}
		if !more {
			wait = time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-s.Spool.Notify():
			if wait > 0 && more { // backing off: a new batch does not cut it short
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
		}
	}
}

func (s *Sender) String() string {
	return fmt.Sprintf("sent=%d rejected=%d dropped_bad=%d", s.Sent, s.Rejected, s.DroppedBad)
}
