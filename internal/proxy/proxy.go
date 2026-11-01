// Package proxy translates between public HTTP semantics and tunnel
// streams. It owns header correctness: hop-by-hop stripping, spoofed
// forwarded-header rejection, relay-credential stripping, and explicit
// proxy metadata (D08, E07-E09). There is exactly one header policy.
package proxy

import (
	"net/http"
	"net/textproto"
	"strings"

	"ocliv/internal/access"
	"ocliv/internal/apperr"
)

// HopByHop lists headers that must never cross the tunnel.
var HopByHop = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "te": true, "trailer": true,
	"transfer-encoding": true, "upgrade": true,
}

// ValidMethods is the v1 method allowlist; CONNECT/TRACE are rejected.
var ValidMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true,
	http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
	http.MethodOptions: true,
}

// CheckRequestSyntax rejects ambiguous HTTP framing before any forwarding
// (E01): conflicting lengths, smuggling variants, malformed bytes, CONNECT,
// absolute-form abuse, unsupported upgrades.
func CheckRequestSyntax(r *http.Request) error {
	if r.Method == http.MethodConnect || r.Method == http.MethodTrace {
		return apperr.E(apperr.CodeBadRequest, "unsupported method", nil)
	}
	if !ValidMethods[r.Method] {
		return apperr.E(apperr.CodeBadRequest, "unsupported method", nil)
	}
	if r.RequestURI != "" && (strings.HasPrefix(r.RequestURI, "http://") || strings.HasPrefix(r.RequestURI, "https://")) {
		return apperr.E(apperr.CodeBadRequest, "absolute-form request URI rejected", nil)
	}
	// net/http already rejects malformed header bytes, bare CR/LF, unknown
	// Transfer-Encoding (501), and conflicting duplicate Content-Length at
	// parse time; here we enforce the semantic layer.
	//
	// NOTE: Go consumes Transfer-Encoding/Content-Length into r.TransferEncoding
	// and r.ContentLength before handlers run. When TE is present, chunked
	// wins deterministically and any CL is dropped by the parser; the relay
	// then forwards a single unambiguous byte stream (never re-framed), so
	// no second parser can disagree. See docs/PROTOCOL.md.
	if len(r.TransferEncoding) > 0 {
		if len(r.TransferEncoding) != 1 || !strings.EqualFold(r.TransferEncoding[0], "chunked") {
			return apperr.E(apperr.CodeBadRequest, "unsupported Transfer-Encoding", nil)
		}
		return nil
	}
	cls := r.Header.Values("Content-Length")
	if len(cls) > 1 {
		// Duplicate Content-Length with differing values is smuggling.
		for _, v := range cls[1:] {
			if v != cls[0] {
				return apperr.E(apperr.CodeBadRequest, "conflicting Content-Length values", nil)
			}
		}
	}
	if r.ContentLength < 0 && r.ContentLength != -1 && r.ContentLength != 0 {
		return apperr.E(apperr.CodeBadRequest, "invalid content length", nil)
	}
	return nil
}

// SanitizeVisitorHeaders strips hop-by-hop, spoofed forwarded, and relay
// credential headers, returning the clean set to send to the agent (D08, E08).
func SanitizeVisitorHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for k, vs := range h {
		ck := strings.ToLower(k)
		if HopByHop[ck] {
			continue
		}
		switch ck {
		case "forwarded", "x-forwarded-host", "x-forwarded-proto",
			"x-forwarded-for", "x-forwarded-port", "x-forwarded-server",
			"x-real-ip", strings.ToLower(access.HeaderName), "cookie":
			continue // handled explicitly below
		}
		if ck == "connection" {
			continue
		}
		out[textproto.CanonicalMIMEHeaderKey(k)] = strings.Join(vs, ", ")
	}
	return out
}

// AppCookies forwards application cookies untouched while dropping the
// reserved relay cookie (E07, C11). Normalization is deliberately minimal:
// cookies are parsed into name/value pairs and re-emitted, preserving all
// application cookies byte-for-byte apart from surrounding whitespace, so
// upstream session semantics never change. Only the relay-owned cookie is
// removed; nothing is ever added.
func AppCookies(r *http.Request) string {
	var kept []string
	for _, c := range r.Cookies() {
		if c.Name == access.CookieName {
			continue
		}
		kept = append(kept, c.Name+"="+c.Value)
	}
	return strings.Join(kept, "; ")
}

// ResponseHeadersToPublic converts agent response headers to the public
// writer, dropping relay-reserved names and malicious Set-Cookie attempts
// for relay cookie names (C11).
func ResponseHeadersToPublic(w http.Header, agentHeaders map[string]string) {
	for k, v := range agentHeaders {
		ck := strings.ToLower(k)
		if HopByHop[ck] {
			continue
		}
		if ck == "set-cookie" {
			// Split conservatively: drop any cookie setting the relay name.
			parts := strings.Split(v, "\n")
			var kept []string
			for _, p := range parts {
				name := strings.TrimSpace(strings.SplitN(p, "=", 2)[0])
				if strings.EqualFold(name, access.CookieName) {
					continue
				}
				kept = append(kept, p)
			}
			for _, p := range kept {
				w.Add("Set-Cookie", p)
			}
			continue
		}
		w.Set(textproto.CanonicalMIMEHeaderKey(k), v)
	}
}

// IsWebSocketUpgrade reports a valid WS handshake request shape.
func IsWebSocketUpgrade(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	conn := strings.ToLower(r.Header.Get("Connection"))
	return strings.Contains(conn, "upgrade")
}

// CheckUpgradeSyntax rejects ambiguous upgrade negotiations before any
// forwarding. A non-empty Upgrade that is not a valid WebSocket handshake
// fails closed: anything else would silently downgrade an upgrade
// negotiation to plain HTTP, misdelivering protocol bytes to the local
// app (E01, D11).
func CheckUpgradeSyntax(r *http.Request) error {
	if r.Header.Get("Upgrade") != "" && !IsWebSocketUpgrade(r) {
		return apperr.E(apperr.CodeBadRequest, "unsupported upgrade", nil)
	}
	return nil
}
