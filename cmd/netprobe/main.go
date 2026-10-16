// Command netprobe checks HTTP(S) endpoints and reports DNS, TCP, TLS and
// HTTP health.
//
//	netprobe check -config targets.json        one-shot check, exit code for scripts/cron/CI
//	netprobe serve -config targets.json        continuous probing + Prometheus /metrics
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
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Vishrut28/netprobe/internal/metrics"
	"github.com/Vishrut28/netprobe/internal/probe"
)

const usage = `netprobe - DNS / TCP / TLS / HTTP endpoint health checker

Usage:
  netprobe check -config targets.json [-json] [-cert-warn-days 14]
  netprobe serve -config targets.json [-listen :9115] [-interval 30s]

Run "netprobe <command> -h" for all flags.
`

type config struct {
	Targets []probe.Target `json:"targets"`
}

func loadConfig(path string) (config, error) {
	var c config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(c.Targets) == 0 {
		return c, errors.New("config has no targets")
	}
	seen := map[string]bool{}
	for i, t := range c.Targets {
		if t.Name == "" || t.URL == "" {
			return c, fmt.Errorf("target %d: name and url are required", i)
		}
		if seen[t.Name] {
			return c, fmt.Errorf("duplicate target name %q", t.Name)
		}
		seen[t.Name] = true
	}
	return c, nil
}

// common flags shared by both subcommands.
type common struct {
	config   string
	timeout  time.Duration
	retries  int
	backoff  time.Duration
	workers  int
	insecure bool
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.config, "config", "targets.json", "path to JSON target config")
	fs.DurationVar(&c.timeout, "timeout", 5*time.Second, "per-attempt timeout")
	fs.IntVar(&c.retries, "retries", 2, "retries after a failed attempt")
	fs.DurationVar(&c.backoff, "backoff", 200*time.Millisecond, "base retry backoff (doubles each retry)")
	fs.IntVar(&c.workers, "workers", 16, "concurrent probes")
	fs.BoolVar(&c.insecure, "insecure", false, "skip TLS certificate verification")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var code int
	switch os.Args[1] {
	case "check":
		code = runCheck(ctx, os.Args[2:], os.Stdout)
	case "serve":
		code = runServe(ctx, os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		code = 2
	}
	os.Exit(code)
}

// runCheck probes once. Exit 0 = all healthy, 1 = something down or a cert
// expiring soon, 2 = usage/config error.
func runCheck(ctx context.Context, args []string, out io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	var c common
	c.register(fs)
	asJSON := fs.Bool("json", false, "print results as JSON")
	warnDays := fs.Float64("cert-warn-days", 14, "fail if a certificate expires within this many days")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(c.config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	p := probe.New(c.timeout, c.retries, c.backoff, c.insecure)
	results := p.RunAll(ctx, cfg.Targets, c.workers)

	healthy := true
	for _, r := range results {
		if !r.Up || (!r.CertExpiry.IsZero() && r.CertDaysLeft < *warnDays) {
			healthy = false
		}
	}

	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	} else {
		printTable(out, results, *warnDays)
	}
	if !healthy {
		return 1
	}
	return 0
}

func ms(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f", float64(d.Microseconds())/1000)
}

func printTable(out io.Writer, results []probe.Result, warnDays float64) {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tSTATUS\tCODE\tDNS ms\tTCP ms\tTLS ms\tTTFB ms\tTOTAL ms\tTLS\tCERT DAYS\tNOTE")
	for _, r := range results {
		status := "UP"
		if !r.Up {
			status = "DOWN"
		}
		cert := "-"
		note := r.Error
		if !r.CertExpiry.IsZero() {
			cert = fmt.Sprintf("%.0f", r.CertDaysLeft)
			if r.CertDaysLeft < warnDays && note == "" {
				note = "certificate expiring soon"
			}
		}
		if r.Attempts > 1 && note == "" {
			note = fmt.Sprintf("recovered after %d attempts", r.Attempts)
		}
		tlsv := r.TLSVersion
		if tlsv == "" {
			tlsv = "-"
		}
		code := "-"
		if r.StatusCode > 0 {
			code = fmt.Sprint(r.StatusCode)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Target, status, code, ms(r.DNS), ms(r.Connect), ms(r.TLS), ms(r.TTFB), ms(r.Total), tlsv, cert, note)
	}
	tw.Flush()
}

// runServe probes on an interval and serves /metrics, /healthz and /readyz.
func runServe(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var c common
	c.register(fs)
	listen := fs.String("listen", ":9115", "address for the metrics server")
	interval := fs.Duration("interval", 30*time.Second, "time between probe rounds")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := loadConfig(c.config)
	if err != nil {
		log.Error("load config", "err", err)
		return 2
	}

	store := metrics.NewStore()
	p := probe.New(c.timeout, c.retries, c.backoff, c.insecure)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		store.WritePrometheus(w)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !store.Ready() {
			http.Error(w, "no probe round completed yet", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ready")
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	go func() {
		log.Info("metrics server listening", "addr", *listen, "targets", len(cfg.Targets), "interval", interval.String())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server", "err", err)
		}
	}()

	// Probe loop: log only state transitions so logs stay useful.
	prev := map[string]bool{}
	round := func() {
		results := p.RunAll(ctx, cfg.Targets, c.workers)
		store.Record(results)
		for _, r := range results {
			if was, ok := prev[r.Target]; !ok || was != r.Up {
				if r.Up {
					log.Info("target up", "target", r.Target, "status", r.StatusCode, "total_ms", r.Total.Milliseconds())
				} else {
					log.Warn("target down", "target", r.Target, "err", r.Error, "attempts", r.Attempts)
				}
			}
			prev[r.Target] = r.Up
		}
	}
	round()
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutCtx)
			return 0
		case <-ticker.C:
			round()
		}
	}
}
