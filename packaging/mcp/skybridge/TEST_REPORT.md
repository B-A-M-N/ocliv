# Verification record (current as of 2026-11-02)

- Environment: repo checkout on Pop!_OS 22.04 (user's PC).
- Node: v22.22.3; `engines` requires `>=22` (reconciled 2026-11-02; the
  old Node 24+ requirement was a scaffold skew, corrected with evidence).
- Run: `npm test` — **81 passed, 0 failed** (includes issuer
  segment-scope, bounded-response, approval-isolation, and
  reconcile/orphan-state regression tests).
- Run: `npx tsc --noEmit` — clean. `npm run build` — server bundle ok
  (React view bundle still unresolvable: `skybridge/vite` subpath missing
  from installed skybridge 2.1.0 — scaffold/SDK skew, view optional).
- Tests are deterministic unit tests with a mocked network boundary,
  plus live-readiness probes that run only with explicit env. They do
  **not** by themselves demonstrate external ChatGPT registration.

Live evidence (public Funnel lab, same date, separate from unit tests):

- Relay rebuilt from HEAD serving 127.0.0.1:18082 behind
  `https://pop-os.tail8d285a.ts.net` (Funnel edge, TLS verified).
- `funnel-oauth` publication republished on its stable route ID after
  lease expiry with OAuth discovery verified (PRM 200, exact resource).
- Authenticated `tools/call ping` through the public URL returned
  `pong:ocliv-oauth-lab-1`; anonymous calls 401; 130 rotating-spoof
  X-Forwarded-For probes shared one admission bucket (120x401 then
  10x429) — visitors cannot choose their apparent source IP.
- Revoked JWT denied remotely (401) after fixture revocation.
- `ocliv-mgmt` route retained but offline (503) while Skybridge is
  down: durable publication state is not tunnel liveness.

This record distinguishes unit qualification (above) from live
ChatGPT/Auth0 management integration, which remains operator-gated
(see SPEC hard gates). No live ChatGPT tool-call response is recorded
here; any such claim without dated, redacted evidence is UNVERIFIED.
