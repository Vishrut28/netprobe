package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Vishrut28/netprobe/internal/probe"
)

func TestWritePrometheus(t *testing.T) {
	s := NewStore()
	if s.Ready() {
		t.Fatal("empty store should not be ready")
	}
	s.Record([]probe.Result{
		{Target: "api", URL: "https://api.example.com", Up: true, StatusCode: 200,
			Total: 120 * time.Millisecond, TLSVersion: "TLS 1.3", TLS: 30 * time.Millisecond,
			CertExpiry: time.Now().Add(48 * time.Hour), CertDaysLeft: 2},
		{Target: `we"ird`, URL: "http://x", Up: false, Error: "boom"},
	})
	s.Record([]probe.Result{{Target: "api", URL: "https://api.example.com", Up: false}})

	var buf bytes.Buffer
	s.WritePrometheus(&buf)
	out := buf.String()

	for _, want := range []string{
		`# TYPE netprobe_up gauge`,
		`netprobe_up{target="api",url="https://api.example.com"} 0`,
		`netprobe_up{target="we\"ird",url="http://x"} 0`,
		`netprobe_checks_total{target="api"} 2`,
		`netprobe_failures_total{target="api"} 1`,
		`# TYPE netprobe_failures_total counter`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
	if !s.Ready() {
		t.Error("store should be ready after Record")
	}
}
