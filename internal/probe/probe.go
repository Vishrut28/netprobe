// Package probe runs HTTP(S) health checks against a target and records
// per-phase timings (DNS, TCP connect, TLS handshake, time-to-first-byte)
// along with TLS certificate details.
package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

// Target is a single endpoint to probe.
type Target struct {
	Name           string `json:"name"`
	URL            string `json:"url"`
	ExpectedStatus int    `json:"expected_status,omitempty"` // 0 means any status < 400
}

// Result captures the outcome of one probe.
type Result struct {
	Target       string        `json:"target"`
	URL          string        `json:"url"`
	Up           bool          `json:"up"`
	StatusCode   int           `json:"status_code"`
	Error        string        `json:"error,omitempty"`
	Attempts     int           `json:"attempts"`
	DNS          time.Duration `json:"dns_ns"`
	Connect      time.Duration `json:"connect_ns"`
	TLS          time.Duration `json:"tls_ns"`
	TTFB         time.Duration `json:"ttfb_ns"`
	Total        time.Duration `json:"total_ns"`
	TLSVersion   string        `json:"tls_version,omitempty"`
	CertExpiry   time.Time     `json:"cert_expiry,omitempty"`
	CertDaysLeft float64       `json:"cert_days_left,omitempty"`
	CheckedAt    time.Time     `json:"checked_at"`
}

// Prober executes probes with a shared HTTP client.
type Prober struct {
	Timeout time.Duration
	Retries int           // extra attempts after the first failure
	Backoff time.Duration // base backoff, doubled on each retry
	client  *http.Client
}

// New returns a Prober. insecure skips TLS verification (for internal
// endpoints with private CAs, and for tests).
func New(timeout time.Duration, retries int, backoff time.Duration, insecure bool) *Prober {
	tr := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: true,                                      // fresh connection each probe so DNS/TCP/TLS are really measured
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // explicit opt-in
	}
	return &Prober{
		Timeout: timeout,
		Retries: retries,
		Backoff: backoff,
		client: &http.Client{
			Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // report the endpoint itself, not where it redirects
			},
		},
	}
}

// Probe checks a target, retrying with exponential backoff on failure.
func (p *Prober) Probe(ctx context.Context, t Target) Result {
	var r Result
	for attempt := 0; attempt <= p.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				r.Error = ctx.Err().Error()
				return r
			case <-time.After(p.Backoff << (attempt - 1)):
			}
		}
		r = p.once(ctx, t)
		r.Attempts = attempt + 1
		if r.Up {
			break
		}
	}
	return r
}

func (p *Prober) once(ctx context.Context, t Target) Result {
	r := Result{Target: t.Name, URL: t.URL, CheckedAt: time.Now()}

	var dnsStart, connStart, tlsStart, start time.Time
	trace := &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:              func(httptrace.DNSDoneInfo) { r.DNS = time.Since(dnsStart) },
		ConnectStart:         func(string, string) { connStart = time.Now() },
		ConnectDone:          func(string, string, error) { r.Connect = time.Since(connStart) },
		TLSHandshakeStart:    func() { tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { r.TLS = time.Since(tlsStart) },
		GotFirstResponseByte: func() { r.TTFB = time.Since(start) },
	}

	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, t.URL, nil)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	req.Header.Set("User-Agent", "netprobe/1.0")

	start = time.Now()
	resp, err := p.client.Do(req)
	if err != nil {
		r.Total = time.Since(start)
		r.Error = err.Error()
		return r
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	r.Total = time.Since(start)
	r.StatusCode = resp.StatusCode

	if resp.TLS != nil {
		r.TLSVersion = tls.VersionName(resp.TLS.Version)
		if len(resp.TLS.PeerCertificates) > 0 {
			r.CertExpiry = resp.TLS.PeerCertificates[0].NotAfter
			r.CertDaysLeft = time.Until(r.CertExpiry).Hours() / 24
		}
	}

	switch {
	case t.ExpectedStatus != 0 && resp.StatusCode != t.ExpectedStatus:
		r.Error = fmt.Sprintf("unexpected status %d (want %d)", resp.StatusCode, t.ExpectedStatus)
	case t.ExpectedStatus == 0 && resp.StatusCode >= 400:
		r.Error = fmt.Sprintf("unhealthy status %d", resp.StatusCode)
	default:
		r.Up = true
	}
	return r
}

// RunAll probes targets concurrently with a bounded worker pool.
// Results come back in the same order as targets.
func (p *Prober) RunAll(ctx context.Context, targets []Target, workers int) []Result {
	if workers < 1 {
		workers = 1
	}
	results := make([]Result, len(targets))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = p.Probe(ctx, targets[i])
			}
		}()
	}
	for i := range targets {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}
