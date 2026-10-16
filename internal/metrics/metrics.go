// Package metrics keeps the latest probe results and renders them in the
// Prometheus text exposition format, with no external dependencies.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/Vishrut28/netprobe/internal/probe"
)

// Store holds the most recent result per target plus cumulative counters.
// It is safe for concurrent use by the prober and HTTP handlers.
type Store struct {
	mu       sync.RWMutex
	latest   map[string]probe.Result
	checks   map[string]uint64
	failures map[string]uint64
}

func NewStore() *Store {
	return &Store{
		latest:   map[string]probe.Result{},
		checks:   map[string]uint64{},
		failures: map[string]uint64{},
	}
}

// Record stores a batch of results.
func (s *Store) Record(results []probe.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range results {
		s.latest[r.Target] = r
		s.checks[r.Target]++
		if !r.Up {
			s.failures[r.Target]++
		}
	}
}

// Ready reports whether at least one probe round has completed.
func (s *Store) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.latest) > 0
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// WritePrometheus renders all metrics in text exposition format.
func (s *Store) WritePrometheus(w io.Writer) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.latest))
	for n := range s.latest {
		names = append(names, n)
	}
	sort.Strings(names)

	gauge := func(name, help string, val func(probe.Result) (float64, bool)) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
		for _, n := range names {
			r := s.latest[n]
			if v, ok := val(r); ok {
				fmt.Fprintf(w, "%s{target=\"%s\",url=\"%s\"} %g\n", name, labelEscaper.Replace(n), labelEscaper.Replace(r.URL), v)
			}
		}
	}
	boolf := func(x bool) float64 {
		if x {
			return 1
		}
		return 0
	}

	gauge("netprobe_up", "1 if the last probe succeeded.",
		func(r probe.Result) (float64, bool) { return boolf(r.Up), true })
	gauge("netprobe_http_status_code", "HTTP status of the last probe.",
		func(r probe.Result) (float64, bool) { return float64(r.StatusCode), r.StatusCode > 0 })
	gauge("netprobe_dns_seconds", "DNS lookup time.",
		func(r probe.Result) (float64, bool) { return r.DNS.Seconds(), true })
	gauge("netprobe_connect_seconds", "TCP connect time.",
		func(r probe.Result) (float64, bool) { return r.Connect.Seconds(), true })
	gauge("netprobe_tls_handshake_seconds", "TLS handshake time.",
		func(r probe.Result) (float64, bool) { return r.TLS.Seconds(), r.TLSVersion != "" })
	gauge("netprobe_ttfb_seconds", "Time to first response byte.",
		func(r probe.Result) (float64, bool) { return r.TTFB.Seconds(), r.StatusCode > 0 })
	gauge("netprobe_total_seconds", "Total probe duration.",
		func(r probe.Result) (float64, bool) { return r.Total.Seconds(), true })
	gauge("netprobe_cert_expiry_days", "Days until the leaf TLS certificate expires.",
		func(r probe.Result) (float64, bool) { return r.CertDaysLeft, !r.CertExpiry.IsZero() })

	counter := func(name, help string, m map[string]uint64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
		for _, n := range names {
			fmt.Fprintf(w, "%s{target=\"%s\"} %d\n", name, labelEscaper.Replace(n), m[n])
		}
	}
	counter("netprobe_checks_total", "Probe rounds run per target.", s.checks)
	counter("netprobe_failures_total", "Failed probe rounds per target.", s.failures)
}
