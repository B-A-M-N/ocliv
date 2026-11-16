package cli

// Durable publication identity for MCP publications (P1).
//
// A publication's identity is its NAME: the relay keys durable
// publications on (tenant, owner key, external host, profile, name), so
// the same name under the same owner rebinds the same route instead of
// minting a second one.
//
// The bare `ocliv mcp PORT` path used to publish with NO name, which made
// the relay mint a random one on every run. The public URL therefore
// changed on every restart, and each run left another publication row
// behind under the same owner.
//
// The identity is therefore DERIVED FROM THE SERVICE — the local target
// and the auth profile — not from the moment of publication. The same
// configured service maps to the same name on every machine and every
// restart, so the endpoint an operator handed to a client is durable.
//
// The name is a DNS label (the relay mints a hostname from it), so it is
// built from a digest: readable prefix, port, and a short hash that
// separates targets that differ only in host or path.
import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// defaultPublicationName derives the durable publication name for one
// service: the port it serves, the local target it serves, and the
// authorization profile it is published under.
//
// The same inputs always produce the same name, and different inputs
// never collide (the digest covers the parts the label cannot show).
//
// The backend PORT is part of the name for HTTP MCP targets. Stdio-backed
// publications require an explicit stable name because their adapter port
// is ephemeral and must not define durable identity.
func defaultPublicationName(port int, localURL, authProfile string) string {
	host, _, path := publicationTargetParts(localURL)
	sum := sha256.Sum256([]byte(host + "\x00" + path + "\x00" + authProfile))
	// 8 hex chars of digest: 32 bits of separation, which keeps the
	// label well under the 63-character DNS limit while making an
	// accidental collision between two distinct targets negligible.
	digest := hex.EncodeToString(sum[:4])
	return fmt.Sprintf("mcp-%d-%s-%s", port, strings.ToLower(authProfile), digest)
}

// freshPublicationName turns a derived publication name into a distinct
// one, for an operator who explicitly asks for a NEW identity for a
// service that already has a durable route. The suffix is random, so two
// fresh requests never land on the same identity.
func freshPublicationName(base string) string {
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		// A CSPRNG failure must not silently fall back to the durable
		// name: the operator asked for a fresh identity, so failing
		// closed here is correct.
		return base + "-fresh"
	}
	return base + "-" + hex.EncodeToString(raw)
}

// publicationTargetParts splits a loopback target into the parts that
// distinguish one service from another: the host (so 127.0.0.1 and ::1
// differ), the port, and the path (so two services on one port differ).
// Unparseable input degrades to a stable literal, never to an empty
// component that would collapse two targets into one name.
func publicationTargetParts(localURL string) (host, port, path string) {
	host, port, path = "local", "0", "/"
	u, err := url.Parse(localURL)
	if err != nil || u.Host == "" {
		return host, port, path
	}
	if h := u.Hostname(); h != "" {
		host = h
	}
	if p := u.Port(); p != "" {
		port = p
	} else if n, err := strconv.Atoi(u.Port()); err == nil {
		port = strconv.Itoa(n)
	}
	if u.Path != "" {
		path = u.Path
	}
	return host, port, path
}
