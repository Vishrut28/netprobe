package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeTLSServerReportsPhasesAndCert(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := New(2*time.Second, 0, 0, true)
	r := p.Probe(context.Background(), Target{Name: "tls", URL: srv.URL})

	if !r.Up || r.StatusCode != 200 {
		t.Fatalf("expected up/200, got up=%v code=%d err=%q", r.Up, r.StatusCode, r.Error)
	}
	if r.TLSVersion == "" || r.TLS <= 0 {
		t.Errorf("expected TLS handshake to be measured, got version=%q dur=%v", r.TLSVersion, r.TLS)
	}
	if r.Connect <= 0 || r.TTFB <= 0 || r.Total < r.TTFB {
		t.Errorf("bad timings: connect=%v ttfb=%v total=%v", r.Connect, r.TTFB, r.Total)
	}
	if r.CertExpiry.IsZero() || r.CertDaysLeft <= 0 {
		t.Errorf("expected certificate expiry, got %v (%.1f days)", r.CertExpiry, r.CertDaysLeft)
	}
}

func TestProbeUnhealthyStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	r := New(time.Second, 0, 0, false).Probe(context.Background(), Target{Name: "x", URL: srv.URL})
	if r.Up || r.StatusCode != 503 || r.Error == "" {
		t.Fatalf("expected down with 503, got up=%v code=%d err=%q", r.Up, r.StatusCode, r.Error)
	}
}

func TestProbeExpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	p := New(time.Second, 0, 0, false)
	if r := p.Probe(context.Background(), Target{Name: "x", URL: srv.URL, ExpectedStatus: 204}); !r.Up {
		t.Errorf("204 expected 204 should be up: %q", r.Error)
	}
	if r := p.Probe(context.Background(), Target{Name: "x", URL: srv.URL, ExpectedStatus: 200}); r.Up {
		t.Errorf("204 expected 200 should be down")
	}
}

func TestProbeRetriesThenRecovers(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := New(time.Second, 3, time.Millisecond, false).Probe(context.Background(), Target{Name: "flaky", URL: srv.URL})
	if !r.Up || r.Attempts != 3 {
		t.Fatalf("expected recovery on attempt 3, got up=%v attempts=%d", r.Up, r.Attempts)
	}
}

func TestProbeTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()

	r := New(50*time.Millisecond, 0, 0, false).Probe(context.Background(), Target{Name: "slow", URL: srv.URL})
	if r.Up || r.Error == "" {
		t.Fatalf("expected timeout failure, got up=%v err=%q", r.Up, r.Error)
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listening any more

	r := New(time.Second, 0, 0, false).Probe(context.Background(), Target{Name: "gone", URL: url})
	if r.Up || r.Error == "" {
		t.Fatalf("expected connection failure, got up=%v", r.Up)
	}
}

func TestRunAllConcurrentAndOrdered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer srv.Close()

	targets := make([]Target, 20)
	for i := range targets {
		targets[i] = Target{Name: string(rune('a' + i)), URL: srv.URL}
	}
	start := time.Now()
	results := New(2*time.Second, 0, 0, false).RunAll(context.Background(), targets, 20)
	elapsed := time.Since(start)

	// 20 x 100ms sequentially would be ~2s; concurrently it should be far less.
	if elapsed > time.Second {
		t.Errorf("RunAll not concurrent: took %v", elapsed)
	}
	for i, r := range results {
		if r.Target != targets[i].Name || !r.Up {
			t.Errorf("result %d: got target=%q up=%v", i, r.Target, r.Up)
		}
	}
}
