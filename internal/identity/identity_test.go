package identity

import (
	"os"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	ch, err := NewChallenge("https://relay.example.test", "v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Nonce) != NonceBytes {
		t.Fatalf("nonce = %d bytes, want %d", len(ch.Nonce), NonceBytes)
	}
	if !ch.ExpiresAt.After(time.Now()) {
		t.Fatal("challenge already expired")
	}
	ts := time.Now().UTC()
	sig := k.Sign(ch.Nonce, ch.Origin, ch.Version, ts, `{"ready":true}`)
	if err := Verify(k.Public(), ch.Nonce, string(k.ID()), ch.Origin, ch.Version, ts, `{"ready":true}`, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	k, _ := Generate()
	other, _ := Generate()
	ch, _ := NewChallenge("https://relay.example.test", "v1")
	ts := time.Now().UTC()
	sig := k.Sign(ch.Nonce, ch.Origin, ch.Version, ts, `{"ready":true}`)
	if err := Verify(k.Public(), ch.Nonce, string(k.ID()), ch.Origin, ch.Version, ts, `{"ready":false}`, sig); err == nil {
		t.Fatal("tampered intent accepted")
	}
	if err := Verify(other.Public(), ch.Nonce, string(k.ID()), ch.Origin, ch.Version, ts, `{"ready":true}`, sig); err == nil {
		t.Fatal("wrong key accepted")
	}
	if err := Verify(k.Public(), ch.Nonce, string(k.ID()), ch.Origin, ch.Version, ts.Add(-time.Hour), `{"ready":true}`, sig); err == nil {
		t.Fatal("stale timestamp accepted")
	}
}

func TestEnrollmentCodeRoundTrip(t *testing.T) {
	code, verifier, err := MintEnrollmentCode()
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEnrollmentCode(code, verifier) {
		t.Fatal("fresh enrollment code rejected")
	}
	if VerifyEnrollmentCode(code+"x", verifier) {
		t.Fatal("tampered enrollment code accepted")
	}
	if VerifyEnrollmentCode(code, "deadbeef") {
		t.Fatal("wrong verifier accepted")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := dir + "/agent.key"
	if err := k.Save(path); err != nil {
		t.Fatal(err)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(back.ID()) != string(k.ID()) {
		t.Fatal("loaded key id mismatch")
	}
	// World-readable key material must be refused.
	world := dir + "/agent-world.key"
	if err := os.WriteFile(world, []byte("AAAA"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(world); err == nil {
		t.Fatal("unsafe-permission key accepted")
	}
}
