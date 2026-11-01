package transport

import (
	"crypto/tls"
	"testing"
)

// checkedTLS is the TLS-edge boundary: WSS must always be verified, and
// plaintext is allowed only for loopback test/dev dials.
func TestCheckedTLSRefusesUnverifiedWSS(t *testing.T) {
	if _, _, err := checkedTLS(nil, "wss://relay.example.test/v1/agent/connect", true); err == nil {
		t.Fatal("wss without tls config accepted")
	}
	if _, _, err := checkedTLS(&tls.Config{InsecureSkipVerify: true}, "wss://relay.example.test/v1/agent/connect", true); err == nil {
		t.Fatal("wss with InsecureSkipVerify accepted")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	got, tlsOn, err := checkedTLS(cfg, "wss://relay.example.test/v1/agent/connect", false)
	if err != nil || !tlsOn || got != cfg {
		t.Fatalf("verified wss rejected: cfg=%v tls=%v err=%v", got == cfg, tlsOn, err)
	}
}

func TestCheckedTLSPlaintextLoopbackOnly(t *testing.T) {
	if _, _, err := checkedTLS(nil, "ws://127.0.0.1:1/x", false); err == nil {
		t.Fatal("plaintext ws accepted without loopback allowance")
	}
	cfg, tlsOn, err := checkedTLS(nil, "ws://127.0.0.1:1/x", true)
	if err != nil || tlsOn || cfg != nil {
		t.Fatal("loopback plaintext dial rejected")
	}
}

func TestIsWSS(t *testing.T) {
	for _, u := range []string{"wss://h/x", "https://h/x"} {
		if !isWSS(u) {
			t.Fatalf("%s not recognized as TLS", u)
		}
	}
	for _, u := range []string{"ws://h/x", "http://h/x", ""} {
		if isWSS(u) {
			t.Fatalf("%s misclassified as TLS", u)
		}
	}
}
