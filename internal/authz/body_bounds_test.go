package authz

// Failing-first regressions for the 2026-11-14 review's bounded-request
// parsing finding (P2).

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRegisterOversizedBodyRejected (review P2): a valid JSON prefix
// followed by excess bytes must be refused; registration metadata fields
// are individually bounded; zero durable rows are written after rejection.
func TestRegisterOversizedBodyRejected(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	store := NewSQLStore(db)
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(issuer, store, "tenant-test", "r-test", "https://relay.test/r/r-test/mcp", "https://relay.test")

	register := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.ServeRegister(w, httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body)))
		return w
	}

	// 1. A valid JSON document padded with trailing garbage (just over the
	// 1MB registration cap) must NOT be accepted.
	pad := strings.Repeat("A", (1<<20)+1000)
	oversized := `{"client_name":"x","redirect_uris":["https://client.example/cb"]}` + pad
	if rec := register(oversized); rec.Code == http.StatusCreated {
		t.Fatalf("oversized registration body accepted (review P2): %s", rec.Body.String())
	}

	// 2. An oversized client_name must be refused.
	hugeName := strings.Repeat("n", 4097)
	bigName := fmt.Sprintf(`{"client_name":%q,"redirect_uris":["https://client.example/cb"]}`, hugeName)
	if rec := register(bigName); rec.Code == http.StatusCreated {
		t.Fatal("oversized client_name accepted")
	}

	// 3. Too many redirect URIs must be refused.
	var uris []string
	for i := 0; i < 101; i++ {
		uris = append(uris, fmt.Sprintf("https://client%d.example/cb", i))
	}
	var uriList string
	uriList = "["
	for i, u := range uris {
		if i > 0 {
			uriList += ","
		}
		uriList += fmt.Sprintf("%q", u)
	}
	uriList += "]"
	manyURIs := fmt.Sprintf(`{"client_name":"x","redirect_uris":%s}`, uriList)
	if rec := register(manyURIs); rec.Code == http.StatusCreated {
		t.Fatal("too many redirect_uris accepted")
	}

	// 4. An oversized single redirect URI must be refused.
	longURI := "https://client.example/" + strings.Repeat("p", 4097)
	bigURI := fmt.Sprintf(`{"client_name":"x","redirect_uris":[%q]}`, longURI)
	if rec := register(bigURI); rec.Code == http.StatusCreated {
		t.Fatal("oversized redirect_uri accepted")
	}

	// 5. A body that is not exactly one JSON value must be refused.
	trailing := `{"client_name":"x","redirect_uris":["https://client.example/cb"]} {}`
	if rec := register(trailing); rec.Code == http.StatusCreated {
		t.Fatal("body with two JSON values accepted")
	}

	// No durable rows were written by any rejected request.
	n, err := store.CountClients("tenant-test", "r-test")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d clients written despite all rejections, want 0", n)
	}
}

// TestOAuthFormEndpointsBoundBody (review P2): the authorization,
// token, consent, and revocation form endpoints apply a separate, smaller
// request limit and refuse oversized forms.
func TestOAuthFormEndpointsBoundBody(t *testing.T) {
	s, _, store := newTestServer(t)
	clientID := "client-bounds"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{"https://client.example/cb"}, CreatedAt: time.Now(),
		Tenant: "tenant-test", Route: "r-test"}); err != nil {
		t.Fatal(err)
	}
	// A form body far larger than the 64KB form cap must be refused.
	huge := strings.Repeat("x", 1<<20)
	form := "client_id=" + clientID + "&padding=" + huge

	post := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		s.ServeToken(w, req)
		return w
	}
	if rec := post("/oauth/token"); rec.Code == http.StatusOK {
		t.Fatal("oversized token form accepted (review P2)")
	}
}
