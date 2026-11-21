# Ocliv Security and Trust Model

This document describes the actual trust model, security boundaries, and
threat considerations for the Ocliv tunneling service. It does not make
claims beyond what the implementation enforces.

---

## Architecture overview

```
PUBLIC INTERNET
      |
      v
+-------------------------------+
|       OCLIV RELAY HOST        |
|                               |
| Caddy — public TLS edge       |
| Relay — loopback listener     |
| SQLite — durable state        |
| DNS API credentials (relay)   |
+-------------+-----------------+
              ^
              | outbound HTTPS/WSS only
              |
+-------------+-----------------+
|      PUBLISHER MACHINE        |
|                               |
| Local application (loopback)  |
| ocliv publisher agent         |
|                               |
| NO public listener            |
| NO Caddy                      |
| NO relay database             |
| NO DNS API credentials        |
+-------------------------------+
```

---

## Public TLS termination

TLS for public visitors terminates at **Caddy** on the relay host. The relay
process itself only listens on loopback or a Unix socket. Caddy proxies
decrypted plaintext to the relay over loopback.

**Implication:** The relay operator (or any process with loopback access on
the relay host) can observe proxied plaintext unless the application protocol
adds its own end-to-end encryption (e.g., HTTPS from visitor to relay, then
the relay sees plaintext HTTP before forwarding to the publisher).

Ocliv does **not** claim end-to-end encryption between visitor and publisher.
If your application requires that property, establish TLS at the application
layer independently of Ocliv.

---

## Publisher isolation

The publisher machine requires:
- An outbound TCP/443 connection to the relay.
- The ocliv binary.
- No inbound firewall rules.
- No Caddy, relay database, or DNS API credentials.

The publisher agent never opens a public inbound listener. All traffic flows
outbound to the relay, which proxies visitor connections back over that
persistent WebSocket/yamux session.

The agent only forwards to loopback destinations (`127.x.x.x`). A relay
instruction to forward to an arbitrary upstream is refused client-side.

---

## Publisher identity model

Each publisher has an Ed25519 key pair generated locally at enrollment time.
Only the public key is shared with the relay. The private key never leaves the
publisher machine.

Authentication uses a one-time challenge from the relay: the publisher signs
the challenge nonce together with the lease intent (port, name, public flag,
access mode). This binds identity to intent — the relay cannot replay the
signature for a different purpose.

---

## Enrollment

One-time enrollment codes authorize a public key to be associated with a
tenant on the relay. Codes are stored as bcrypt/scrypt verifiers on the relay
— the plaintext code is never persisted.

Enrollment codes from `ocliv relay issue-enroll` are single-use and
time-limited (default 24 hours). The `--out FILE` option writes codes to a
mode-0600 file rather than stdout.

Code files passed to `ocliv login --code-file PATH` are opened with
`O_NOFOLLOW` and must be regular files with mode 0600 and correct ownership.

---

## Public exposure policy

Publishing a tunnel as publicly accessible (no authentication gate) requires
**both**:

1. The publisher requests `--public` (or `--access-mode public`).
2. The tenant's relay policy permits public exposure (`allow_public=true`).

The default is `allow_public=false`. Newly enrolled tenants cannot create
public leases until the relay operator explicitly enables it:

```
ocliv relay tenants policy set TENANT --allow-public=true
```

This check is enforced **server-side** on the relay. A modified publisher
client that bypasses the CLI check will still be denied by the relay.

---

## Relay compromise implications

If the relay host is compromised:
- The attacker can observe all proxied traffic (plaintext, post-TLS).
- The attacker can mint enrollment codes and authorize new publishers.
- The attacker can revoke existing publishers.
- The attacker has access to the relay's SQLite database and visitor session
  tokens.
- The attacker cannot retroactively decrypt historical traffic if forward
  secrecy was achieved at the TLS layer.
- The attacker cannot access publisher private keys (never sent to the relay).

---

## Caddy/public edge trust boundary

The relay trusts Caddy to terminate TLS correctly and to present the
`X-Forwarded-For` header honestly. In the standard deployment Caddy runs on
the same host as the relay, so this trust is equivalent to trusting the relay
host.

If Caddy is misconfigured to forward the `X-Forwarded-For` header from
untrusted upstream sources, visitors could spoof apparent client IPs. The
relay sanitizes other forwarded headers before passing them to publisher
applications.

---

## Management signature and replay resistance

Relay management operations (publishing, key rotation, revocation, policy
changes) require a time-stamped, nonce-bound Ed25519 signature
(`ocliv-mgmt-v2` for body-bearing mutations). The relay enforces:

- Nonce is single-use; replays are rejected.
- Timestamp must be within a narrow window.
- For body-bearing mutations: SHA-256 of the request body is signed, binding
  the signature to the exact request content.
- Redirect following is disabled on the management client. Auth headers are
  never forwarded to redirect targets.

---

## Revocation

Key revocation is durable in SQLite. A revoked key cannot attach new sessions
or be accepted in management requests. Terminal lease states (REVOKED, CLOSED,
EXPIRED) are preserved — they are not deleted. Backup restore does not permit
rollback of revocations.

---

## Key rotation

Key rotation proves possession of both the old and new key. It transfers all
leases and publication ownership atomically in a single SQLite transaction.

---

## Access control

By default, published services are protected (access-token gate). Protected
services require a share token for visitor access. Tokens are single-use by
default and time-limited.

Public services (no token gate) require explicit operator approval via tenant
policy in addition to the publisher request.

---

## No Tailscale requirement

Ocliv has no dependency on Tailscale or any VPN. Publisher-to-relay
connectivity uses standard HTTPS/WSS over the public internet.

---

## What Ocliv does NOT protect against

- Relay operator visibility into proxied traffic (by design — relay terminates
  TLS).
- Application-layer vulnerabilities in the publisher's local service.
- An attacker with access to the relay host database (revocation is durable
  but the relay itself is the authority).
- Brute-force attacks on visitor session tokens (tokens are high-entropy but
  rate limiting is per-lease, not globally unbounded).
