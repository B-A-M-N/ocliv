package authz

// Failing-first regression for the second review's parser finding: the
// registration handler's "exactly one JSON value" check only rejected a
// SECOND VALID value. A valid object followed by MALFORMED trailing bytes
// (a syntax error other than io.EOF on the second decode) was accepted,
// despite the handler claiming to require exactly one JSON value.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A valid registration object followed by garbage must be refused with
// zero durable writes. Pre-fix the second decode returns a syntax error
// (not io.EOF), which the handler allowed to pass, registering the client.
func TestRegisterRejectsMalformedTrailingJSON(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	store := NewSQLStore(db)
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(issuer, store, "tenant-test", "r-test", "https://relay.test/r/r-test/mcp", "https://relay.test")

	good := `{"client_name":"trail","redirect_uris":["https://client.example/cb"],"token_endpoint_auth_method":"none"}`
	cases := map[string]string{
		"trailing_garbage":  good + "garbage",
		"trailing_brace":    good + "}",
		"trailing_junk_obj": good + `{"x":1}`,
	}
	for name, body := range cases {
		w := httptest.NewRecorder()
		s.ServeRegister(w, httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body)))
		if w.Code == http.StatusOK || w.Code == http.StatusCreated {
			t.Fatalf("%s: malformed trailing bytes accepted (status %d): %s", name, w.Code, w.Body.String())
		}
	}
	// Zero durable writes after every rejection.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM authz_clients`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d client rows written despite malformed trailing JSON", n)
	}
}

var _ = fmt.Sprintf // keep fmt import if unused in future edits
