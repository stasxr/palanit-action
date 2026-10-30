# PALANIT Security Check — GitHub Action

Run PALANIT's **passive** web-security scanner against a URL on every push or deploy, and fail
the build when real issues appear. It checks TLS (version, legacy downgrade, certificate health),
security headers (HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP),
cookie flags, CORS misconfiguration, mixed content, SRI, exposed paths (`/.git`, `/.env`, metrics,
API specs, source maps, secrets), email auth (SPF/DMARC/DKIM/DNSSEC/CAA/MTA-STS/TLS-RPT/BIMI/DANE),
subdomain-takeover signals and an AI-crawler policy — the same battery as
<https://palanit.com/security-check>.

It sends **no attack traffic** — only ordinary GETs, a TLS negotiation and DNS lookups.

## Usage

```yaml
# .github/workflows/security.yml
name: Security
on: [push]
jobs:
  palanit:
    runs-on: ubuntu-latest
    steps:
      - uses: stasxr/palanit-action@v1
        with:
          url: https://your-site.com
          fail-on: high        # fail on a FAIL finding this severe or worse
          min-grade: C         # (optional) also fail if the grade drops below C
```

The step annotates the run with each finding and writes a grade summary to the job page. Use the
outputs downstream:

```yaml
      - uses: stasxr/palanit-action@v1
        id: palanit
        with: { url: https://your-site.com }
      - run: echo "Graded ${{ steps.palanit.outputs.grade }} (${{ steps.palanit.outputs.score }}/100)"
```

With an API key (lifts the per-IP limit, gives you a daily quota) — pass it from a secret:

```yaml
      - uses: stasxr/palanit-action@v1
        with:
          url: https://your-site.com
          api-key: ${{ secrets.PALANIT_API_KEY }}
```

### Inputs

| Input       | Default               | Description |
|-------------|-----------------------|-------------|
| `url`       | — (required)          | The URL or domain to scan. |
| `fail-on`   | `high`                | Fail on a **FAIL** finding at this severity or worse: `high` \| `medium` \| `low` \| `never`. |
| `min-grade` | `none`                | Also fail when the letter grade is below this: `A+` \| `A` \| `B` \| `C` \| `D` \| `F` \| `none`. |
| `api`       | `https://palanit.com` | API base URL (override only if self-hosting). |
| `api-key`   | — (optional)          | Scoped key (`plnt_live_…`). Lifts the anonymous per-IP limit and applies your plan's daily quota. **Store it as a secret.** |

### Outputs

| Output  | Description                    |
|---------|--------------------------------|
| `grade` | Overall letter grade (`A+`…`F`). |
| `score` | 0–100 score.                   |

## Public JSON API

The action is a thin wrapper over the public endpoint. Call it directly from anything:

```bash
curl -s -X POST https://palanit.com/api/sitecheck \
  -H 'Content-Type: application/json' \
  -d '{"url":"example.com"}'
```

### Request

`POST /api/sitecheck` · `Content-Type: application/json`

```json
{ "url": "example.com" }
```

`url` may be a bare domain or a full URL (max 2000 chars). The scan is passive and refuses
private/internal addresses and off-site redirects.

### Response

```jsonc
{
  "ok": true,
  "domain": "example.com",
  "reachable": true,
  "final_url": "https://example.com/",
  "grade": "A",                 // A+ … F
  "score": 88,                  // 0–100 (fail/warn penalise by severity; info/na/pass are neutral)
  "summary": { "fail": 0, "warn": 3, "pass": 21, "info": 9, "na": 0 },
  "checks": [
    {
      "id": "csp",
      "status": "warn",         // pass | warn | fail | info | na
      "severity": "medium",     // high | medium | low | info
      "en": { "title": "Weak CSP", "detail": "…", "fix": "…" },
      "ru": { "title": "Слабый CSP", "detail": "…", "fix": "…" },
      "evidence": "default-src 'self'; …"
    }
    // …one object per check
  ]
}
```

### Authentication (optional)

Send a scoped key to lift the anonymous per-IP limit and get a durable per-key daily quota:

```bash
curl -s -X POST https://palanit.com/api/sitecheck \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer plnt_live_xxxxxxxx…' \
  -d '{"url":"example.com"}'
# (an `X-API-Key: plnt_live_…` header works too)
```

Keyed responses carry `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` (next UTC
midnight) and `X-Palanit-Plan`. Check a key's plan and remaining quota without spending any:

```bash
curl -s https://palanit.com/api/keys/me -H 'Authorization: Bearer plnt_live_…'
# { "ok": true, "plan": "pro", "daily_quota": 5000, "used_today": 12, "remaining": 4988, … }
```

### Error responses

`{ "ok": false, "error": "<code>" }` with codes: `invalid_url` (400), `invalid_key` (401),
`scope_denied` (403), `rate_limited` (429), `busy` (429), `domain_cooldown` (429),
`quota_exceeded` (429). A `{ "ok": true, "reachable": false }` means the target could not be
fetched (private host or off-site redirect).

### Rate limits & tiers

| Tier            | How                              | Limit |
|-----------------|----------------------------------|-------|
| Free / anon     | no key                           | ~5 scans / 10 min **per source IP** (+ a global soft cap) |
| Keyed — free    | `plnt_live_…` key                | 200 scans / day (per key), no per-IP throttle |
| Keyed — pro     | `plnt_live_…` key (Pro)          | 5 000 scans / day (per key) |

A per-target cooldown (2 / 3 min on the resolved IP) and the global cap apply to **everyone** — they
protect third-party targets and our capacity, so even a Pro key can't hammer one domain. Daily
counters reset at UTC midnight. CI that scans one URL per push stays within the free/anon tier; a
key is for bursty matrix builds, dashboards, and higher volume. Keys are issued by PALANIT — ask at
<https://palanit.com/support> (self-serve issuance is coming with Pro billing).

---

Passive checks on publicly observable responses — not an exploit attempt. Confirm findings against
your own configuration. Active tests (DoS/WAF probes) are available for domains you verify you own,
in PALANIT Pro.
