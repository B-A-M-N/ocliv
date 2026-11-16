package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ocliv/internal/config"
	"ocliv/internal/identity"
)

type renewalRoundTripper func(*http.Request) (*http.Response, error)

func (f renewalRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func renewalRunner(t *testing.T, transport http.RoundTripper, interval time.Duration) *Runner {
	t.Helper()
	k, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return &Runner{
		Cfg: config.Agent{RelayURL: "https://relay.example.test", TTLSeconds: 12 * 60 * 60},
		Key: k, KeyID: string(k.ID()), RenewalTransport: transport, renewalInterval: interval,
	}
}

func renewalReply(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestRenewalLoopSignsCurrentGenerationAndSurvivesRepeatedRenewal(t *testing.T) {
	var calls atomic.Int32
	var runner *Runner
	runner = renewalRunner(t, renewalRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.Path != "/v1/agent/lease/lease-a/renew/9/43200/route-a" {
			t.Errorf("renew request = %s %s", req.Method, req.URL.Path)
		}
		ts, err := time.Parse(time.RFC3339Nano, req.Header.Get("X-Ocliv-TS"))
		if err != nil {
			t.Errorf("timestamp: %v", err)
		}
		nonce := req.Header.Get("X-Ocliv-Nonce")
		sig, err := base64.StdEncoding.DecodeString(req.Header.Get("X-Ocliv-Sig"))
		if err != nil || !ed25519.Verify(runner.Key.Public(), MgmtMessage(runner.KeyID, req.Method, req.URL.Path, ts, nonce), sig) {
			t.Error("renewal request signature failed verification")
		}
		calls.Add(1)
		exp := time.Now().UTC().Add(12 * time.Hour).Format(time.RFC3339Nano)
		return renewalReply(http.StatusOK, fmt.Sprintf(`{"lease_expires_at":%q}`, exp)), nil
	}), 10*time.Millisecond)
	runner.SetRenewalPublication("route-a")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var callbacks atomic.Int32
	runner.OnRenewal = func(status LeaseRenewalStatus) {
		if status.Result != "renewed" || status.ExpiresAt.IsZero() {
			t.Errorf("renewal status = %+v", status)
		}
		if callbacks.Add(1) == 3 {
			cancel()
		}
	}
	err := runner.renewalLoop(ctx, Attached{LeaseID: "lease-a", Generation: 9, ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339Nano)}, func() {})
	if err != context.Canceled {
		t.Fatalf("renewal loop error=%v, want context cancellation", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("renewal calls=%d, want 3", calls.Load())
	}
}

func TestRenewalLoopAccelerated24HourEndurance(t *testing.T) {
	var calls atomic.Int32
	clock := time.Now().UTC()
	var simulatedElapsed time.Duration
	var runner *Runner
	runner = renewalRunner(t, renewalRoundTripper(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		exp := runner.renewalTime().Add(12 * time.Hour).Format(time.RFC3339Nano)
		return renewalReply(http.StatusOK, fmt.Sprintf(`{"lease_expires_at":%q}`, exp)), nil
	}), 5*time.Millisecond)
	runner.renewalNow = func() time.Time { return clock }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner.OnRenewal = func(status LeaseRenewalStatus) {
		if status.Result != "renewed" {
			t.Errorf("renewal result=%q", status.Result)
		}
		// Each accelerated interval represents four lease-hours. Advancing
		// the injected clock exercises expiry arithmetic across seven cycles.
		clock = clock.Add(4 * time.Hour)
		simulatedElapsed += 4 * time.Hour
		if simulatedElapsed > 24*time.Hour {
			cancel()
		}
	}
	err := runner.renewalLoop(ctx, Attached{LeaseID: "lease-a", Generation: 4, ExpiresAt: clock.Add(12 * time.Hour).Format(time.RFC3339Nano)}, func() {})
	if err != context.Canceled || calls.Load() != 7 || simulatedElapsed <= 24*time.Hour {
		t.Fatalf("accelerated endurance err=%v renewals=%d simulated=%s, want >24h", err, calls.Load(), simulatedElapsed)
	}
}

func TestRenewalDelayUsesRemainingAuthoritativeExpiry(t *testing.T) {
	runner := renewalRunner(t, renewalRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("unused")
	}), 0)
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	runner.renewalNow = func() time.Time { return now }
	long := runner.renewalDelay(now.Add(12 * time.Hour))
	resumed := runner.renewalDelay(now.Add(10 * time.Minute))
	if long < 7*time.Hour || long > 8*time.Hour {
		t.Fatalf("12h remaining renewal delay=%s, want about 7h59m", long)
	}
	if resumed < 4*time.Minute || resumed > 6*time.Minute {
		t.Fatalf("10m remaining renewal delay=%s, want about 5m", resumed)
	}
}

func TestRenewalRetriesNetworkInterruptionBeforeExpiry(t *testing.T) {
	var calls atomic.Int32
	runner := renewalRunner(t, renewalRoundTripper(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return nil, fmt.Errorf("relay restart")
		}
		exp := time.Now().UTC().Add(12 * time.Hour).Format(time.RFC3339Nano)
		return renewalReply(http.StatusOK, fmt.Sprintf(`{"lease_expires_at":%q}`, exp)), nil
	}), 10*time.Millisecond)
	runner.renewalRetryInterval = 20 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	var succeeded atomic.Bool
	runner.OnRenewal = func(status LeaseRenewalStatus) {
		if status.Result == "renewed" {
			succeeded.Store(true)
			cancel()
		}
	}
	err := runner.renewalLoop(ctx, Attached{LeaseID: "lease-a", Generation: 3, ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339Nano)}, func() {})
	if err != context.Canceled || !succeeded.Load() || calls.Load() != 2 {
		t.Fatalf("loop err=%v success=%v calls=%d", err, succeeded.Load(), calls.Load())
	}
}

func TestRenewalAuthorizationDenialStopsWithoutRebind(t *testing.T) {
	var closed atomic.Bool
	runner := renewalRunner(t, renewalRoundTripper(func(*http.Request) (*http.Response, error) {
		return renewalReply(http.StatusForbidden, "forbidden"), nil
	}), 10*time.Millisecond)
	err := runner.renewalLoop(context.Background(), Attached{LeaseID: "lease-a", Generation: 3, ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339Nano)}, func() { closed.Store(true) })
	if !IsPermanent(err) || !closed.Load() {
		t.Fatalf("authorization denial err=%v closed=%v", err, closed.Load())
	}
}

func TestRenewalGoneStopsPublisherPermanently(t *testing.T) {
	var closed atomic.Bool
	runner := renewalRunner(t, renewalRoundTripper(func(*http.Request) (*http.Response, error) {
		return renewalReply(http.StatusGone, "publication is no longer bound"), nil
	}), 10*time.Millisecond)
	runner.SetRenewalPublication("deleted-route")
	err := runner.renewalLoop(context.Background(), Attached{LeaseID: "lease-a", Generation: 3, ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339Nano)}, func() { closed.Store(true) })
	if !IsPermanent(err) || !closed.Load() || !strings.Contains(err.Error(), "publication is no longer available") {
		t.Fatalf("gone response err=%v closed=%v", err, closed.Load())
	}
}
