package access

import (
	"net/http"
	"testing"
)

func TestTokenVerifyRoundTrip(t *testing.T) {
	tok, err := Mint("visitor")
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(tok.Raw, tok.Verifier) {
		t.Fatal("fresh token rejected")
	}
	if Verify(tok.Raw+"x", tok.Verifier) {
		t.Fatal("tampered token accepted")
	}
	if Verify(tok.Raw, "") {
		t.Fatal("empty verifier accepted")
	}
}

func TestCheckCSRF(t *testing.T) {
	mk := func(method, origin string) *http.Request {
		r, _ := http.NewRequest(method, "http://x/", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}
	if err := CheckCSRF(mk("POST", ""), "http://t.example.com", true); err != nil {
		t.Fatal("header-token request rejected")
	}
	if err := CheckCSRF(mk("GET", ""), "http://t.example.com", false); err != nil {
		t.Fatal("safe method rejected")
	}
	if err := CheckCSRF(mk("POST", ""), "http://t.example.com", false); err == nil {
		t.Fatal("cookie POST without Origin accepted")
	}
	if err := CheckCSRF(mk("POST", "http://evil.com"), "http://t.example.com", false); err == nil {
		t.Fatal("Origin mismatch accepted")
	}
	if err := CheckCSRF(mk("POST", "http://t.example.com"), "http://t.example.com", false); err != nil {
		t.Fatalf("exact Origin rejected: %v", err)
	}
}

func TestCheckUpgradeOrigin(t *testing.T) {
	mk := func(origin string) *http.Request {
		r, _ := http.NewRequest("GET", "http://x/ws", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}
	if err := CheckUpgradeOrigin(mk(""), "http://t.example.com", true); err != nil {
		t.Fatal("header-token upgrade rejected")
	}
	if err := CheckUpgradeOrigin(mk(""), "http://t.example.com", false); err == nil {
		t.Fatal("upgrade without Origin accepted")
	}
	if err := CheckUpgradeOrigin(mk("http://t.example.com.evil.com"), "http://t.example.com", false); err == nil {
		t.Fatal("suffix-match Origin accepted")
	}
}

func TestMintRowIDUniqueNonSecret(t *testing.T) {
	a, err := MintRowID()
	if err != nil || a == "" {
		t.Fatalf("MintRowID: %v %q", err, a)
	}
	b, err := MintRowID()
	if err != nil || b == "" || b == a {
		t.Fatalf("MintRowID not unique: %q %q err=%v", a, b, err)
	}
	// Row IDs must not collide with the bearer namespace: a bearer
	// minted for cookies must never equal a stored row id format that
	// could be confused for one, and vice versa.
	s, err := MintSessionID()
	if err != nil {
		t.Fatal(err)
	}
	if a == s {
		t.Fatal("row ID equals a session bearer")
	}
}
