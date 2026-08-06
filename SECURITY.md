# Security Policy

## Supported versions

Only the latest release gets security fixes. This is a small, actively-maintained single-file proxy — there's no long-term-support branch, and `update.sh --check-only` (bare-metal) or Watchtower (Docker, see the README) make staying current low-effort. If you're on an older version, please update first before reporting an issue, unless you have reason to believe it also affects the latest release.

## Reporting a vulnerability

**Please don't open a public GitHub issue for a security vulnerability.** Doing so discloses it to anyone before a fix is available.

Instead, use GitHub's private reporting:

1. Go to the [Security tab](https://github.com/PumbaLP/CrowdSec-Smart-AbuseIPDB-Proxy/security) of this repository
2. Click **"Report a vulnerability"**
3. Describe the issue — what it affects, how to reproduce it, and its impact if you can assess it

This opens a private conversation visible only to you and the maintainer, and lets you optionally request a CVE once a fix is out.

If you'd rather not use GitHub's flow, open a regular issue asking to be contacted privately, without any vulnerability details in it.

## What's in scope

Roughly, in order of how much it'd matter:

- The proxy leaking or mishandling the AbuseIPDB API key (primary or fallback), the CrowdSec bouncer API key used by `--reconcile`, or any configured notification credentials (Gotify/ntfy/Slack/Discord/Matrix/Telegram/Home Assistant tokens)
- Anything letting the local HTTP endpoint (normally bound to `127.0.0.1` only) be reached, spoofed, or abused from outside its intended scope
- Cache corruption or injection that could cause a false report to AbuseIPDB, or suppress a real one
- Supply-chain concerns: a compromised dependency, a tampered published Docker image, or a GitHub Actions workflow issue (the release pipeline pins actions to commit SHA and signs published images with cosign for exactly this reason — see "Docker" in the README for how to verify a pull)
- `install.sh`/`uninstall.sh`/`update.sh` doing something unexpected to the host outside `/etc/abuseipdb-proxy`, `/var/lib/abuseipdb-proxy`, and the systemd units they manage

Things like "the config file needs a real API key to work" or "the proxy trusts input from a locally-running, already-privileged CrowdSec" aren't really vulnerabilities in the sense this policy is for — that's the intended trust boundary. Open a normal issue for those if something still seems off, and I'm happy to talk it through.

## Response

This is a solo-maintained open-source project on a best-effort basis, not a company with an SLA — but security reports get priority over everything else. Expect an initial response within a few days.
