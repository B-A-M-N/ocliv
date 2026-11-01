# Ocliv tailnet staging qualification harness.
#
# Roles:
#   RELAY_HOST (laptop, 10.9.66.20): Caddy :443 -> relay 127.0.0.1:8080
#   AGENT_HOST (main PC): `ocliv 3000` against https://relay.ocliv.test
#   VISITOR: any third tailnet device (or the agent PC itself with --resolve)
#
# Env (export before running):
#   RELAY_IP   laptop tailnet IPv4 (default 10.9.66.20)
#   STAGING_CA path to the lab CA root (ocliv-root.crt copied from laptop)
#   LEASE_HOST tunnel hostname under test (default demo.t.ocliv.test)
#
# Required local setup (agent/visitor machine):
#   echo "$RELAY_IP relay.ocliv.test $LEASE_HOST" | sudo tee -a /etc/hosts
#   # plus trust $STAGING_CA in the OS store (staging-only; remove after lab)
#
# What this does NOT prove: public DNS, ACME/DNS-01, public internet
# reachability. Those stay NOT VERIFIED for production.
#
# Run order: check-edge.sh -> check-forwarding.sh -> check-recovery.sh
