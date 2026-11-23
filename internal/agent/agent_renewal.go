package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/B-A-M-N/ocliv/internal/config"
)

const (
	renewalRequestTimeout = 10 * time.Second
	renewalRetryMax       = 30 * time.Second
	renewalExpiryMargin   = 2 * time.Second
	renewalSafetyMax      = 2 * time.Minute
)

// LeaseRenewalStatus is the result shown by the publisher and doctor.
type LeaseRenewalStatus struct {
	At        time.Time
	ExpiresAt time.Time
	Result    string
}

var errRenewalRequiresRebind = errors.New("lease renewal requires a fresh session")

func (rn *Runner) renewalTime() time.Time {
	if rn.renewalNow != nil {
		return rn.renewalNow()
	}
	return time.Now()
}

// SetRenewalPublication binds renewals to the durable publication currently
// owned by this publisher. Empty is valid for generic non-publication leases.
func (rn *Runner) SetRenewalPublication(routeID string) {
	rn.renewalMu.Lock()
	rn.renewalPublication = routeID
	rn.renewalMu.Unlock()
}

func (rn *Runner) renewalPublicationID() string {
	rn.renewalMu.RLock()
	defer rn.renewalMu.RUnlock()
	if rn.renewalPublication == "" {
		return "none"
	}
	return rn.renewalPublication
}

// renewalDelay schedules from the authoritative remaining expiry, not the
// configured original TTL. It leaves a proportional safety window and jitters
// only earlier, so a resumed lease can never sleep past its usable deadline.
func (rn *Runner) renewalDelay(expiresAt time.Time) time.Duration {
	if rn.renewalInterval > 0 {
		return rn.renewalInterval
	}
	remaining := expiresAt.Sub(rn.renewalTime())
	if remaining <= 0 {
		return 0
	}
	safety := min(renewalSafetyMax, remaining/5)
	safety = max(safety, renewalExpiryMargin)
	window := remaining - safety
	if window <= 0 {
		return 0
	}
	d := window * 2 / 3
	// Spread renewals but never delay beyond the safety boundary.
	d = time.Duration(float64(d) * (0.9 + 0.1*rand01()))
	return max(time.Second, min(d, window))
}

func (rn *Runner) renewalHTTPClient() (*http.Client, error) {
	client := &http.Client{
		Timeout: renewalRequestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if rn.RenewalTransport != nil {
		client.Transport = rn.RenewalTransport
		return client, nil
	}
	pool, err := config.CertPool()
	if err != nil {
		return nil, err
	}
	if pool != nil {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	}
	return client, nil
}

func (rn *Runner) renewLease(ctx context.Context, client *http.Client, att Attached) (time.Time, int, error) {
	if rn.Cfg.TTLSeconds <= 0 {
		return time.Time{}, 0, nil
	}
	path := fmt.Sprintf("/v1/agent/lease/%s/renew/%d/%d/%s", att.LeaseID, att.Generation, rn.Cfg.TTLSeconds, rn.renewalPublicationID())
	nonce, err := MgmtNonce()
	if err != nil {
		return time.Time{}, 0, err
	}
	ts := rn.renewalTime().UTC()
	sig := ed25519.Sign(rn.Key.Private(), MgmtMessage(rn.KeyID, http.MethodPost, path, ts, nonce))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(rn.Cfg.RelayURL, "/")+path, nil)
	if err != nil {
		return time.Time{}, 0, err
	}
	req.Header.Set("X-Ocliv-Key", rn.KeyID)
	req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
	req.Header.Set("X-Ocliv-Nonce", nonce)
	req.Header.Set("X-Ocliv-Sig", base64.StdEncoding.EncodeToString(sig))
	resp, err := client.Do(req)
	if err != nil {
		return time.Time{}, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return time.Time{}, resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, resp.StatusCode, fmt.Errorf("relay renewal status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var result struct {
		ExpiresAt string `json:"lease_expires_at"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return time.Time{}, resp.StatusCode, fmt.Errorf("decoding renewal response: %w", err)
	}
	expiry, err := time.Parse(time.RFC3339Nano, result.ExpiresAt)
	if err != nil || !expiry.After(rn.renewalTime()) {
		return time.Time{}, resp.StatusCode, fmt.Errorf("relay returned invalid renewal expiry %q", result.ExpiresAt)
	}
	return expiry, resp.StatusCode, nil
}

// renewalLoop keeps one attached generation alive. Authorization denials
// stop the publisher; stale or expired sessions use the normal authenticated
// reconnect-and-rebind path.
func (rn *Runner) renewalLoop(ctx context.Context, att Attached, closeSession func()) error {
	if rn.Cfg.TTLSeconds <= 0 {
		return nil
	}
	ttl := time.Duration(rn.Cfg.TTLSeconds) * time.Second
	expiresAt, err := time.Parse(time.RFC3339Nano, att.ExpiresAt)
	if err != nil {
		expiresAt = rn.renewalTime().Add(ttl)
	}
	client, err := rn.renewalHTTPClient()
	if err != nil {
		return Permanent(fmt.Errorf("lease renewal TLS configuration: %w", err))
	}
	defer client.CloseIdleConnections()
	delay := rn.renewalDelay(expiresAt)
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		requestTimeout := min(renewalRequestTimeout, expiresAt.Sub(rn.renewalTime())-renewalExpiryMargin)
		if requestTimeout <= 0 {
			closeSession()
			return errRenewalRequiresRebind
		}
		attemptCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		expiry, status, renewErr := rn.renewLease(attemptCtx, client, att)
		cancel()
		at := rn.renewalTime().UTC()
		if renewErr == nil {
			expiresAt = expiry
			if rn.OnRenewal != nil {
				rn.OnRenewal(LeaseRenewalStatus{At: at, ExpiresAt: expiresAt, Result: "renewed"})
			}
			delay = rn.renewalDelay(expiresAt)
			continue
		}
		if rn.OnRenewal != nil {
			rn.OnRenewal(LeaseRenewalStatus{At: at, ExpiresAt: expiresAt, Result: renewErr.Error()})
		}
		if status == http.StatusForbidden || status == http.StatusUnauthorized || status == http.StatusGone {
			closeSession()
			if status == http.StatusGone {
				return Permanent(fmt.Errorf("lease renewal stopped because its publication is no longer available: %w", renewErr))
			}
			return Permanent(fmt.Errorf("lease renewal denied; check publisher authorization: %w", renewErr))
		}
		remaining := expiresAt.Sub(rn.renewalTime())
		if status == http.StatusConflict || status == http.StatusNotFound || remaining <= renewalExpiryMargin {
			closeSession()
			return errRenewalRequiresRebind
		}
		delay = min(renewalRetryMax, rn.renewalDelay(expiresAt)/4)
		if rn.renewalRetryInterval > 0 {
			delay = rn.renewalRetryInterval
		}
		if delay < time.Second && remaining > renewalExpiryMargin+time.Second {
			delay = time.Second
		}
		if remaining <= delay+renewalExpiryMargin {
			closeSession()
			return errRenewalRequiresRebind
		}
	}
}
