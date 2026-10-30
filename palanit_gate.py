#!/usr/bin/env python3
"""PALANIT security-check CI gate.

Scans a URL with the public PALANIT passive web-security API and fails the build on findings
at or above a severity threshold (and, optionally, when the letter grade is below a minimum).
Standard library only — runs on any GitHub-hosted runner with Python 3.

Env (set by action.yml):
  PALANIT_URL        the URL / domain to scan (required)
  PALANIT_FAIL_ON    high | medium | low | never   (default: high)
  PALANIT_MIN_GRADE  A+ | A | B | C | D | F | none  (default: none)
  PALANIT_API        API base URL (default: https://palanit.com)
  PALANIT_API_KEY    optional scoped key (plnt_live_…); lifts the per-IP limit, applies plan quota
"""
import json
import os
import sys
import urllib.error
import urllib.request

API = os.environ.get("PALANIT_API", "https://palanit.com").rstrip("/")
URL = os.environ.get("PALANIT_URL", "").strip()
API_KEY = os.environ.get("PALANIT_API_KEY", "").strip()
FAIL_ON = os.environ.get("PALANIT_FAIL_ON", "high").strip().lower()
MIN_GRADE = os.environ.get("PALANIT_MIN_GRADE", "none").strip()

SEV = {"high": 3, "medium": 2, "low": 1, "info": 0}
GRADES = ["F", "D", "C", "B", "A", "A+"]  # rank = index (higher is better)


def gh(kind: str, msg: str) -> None:
    # GitHub Actions annotation (kind = error | warning | notice)
    print(f"::{kind}::{msg.replace(chr(10), ' ')}")


def _append(env_var: str, text: str) -> None:
    path = os.environ.get(env_var)
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)
    except Exception:
        pass


def summary(md: str) -> None:
    _append("GITHUB_STEP_SUMMARY", md + "\n")


def output(key: str, value) -> None:
    _append("GITHUB_OUTPUT", f"{key}={value}\n")


def die(msg: str) -> None:
    gh("error", msg)
    sys.exit(1)


def title(c: dict) -> str:
    return (c.get("en") or {}).get("title") or c.get("id") or "check"


def detail(c: dict) -> str:
    return (c.get("en") or {}).get("detail") or ""


def main() -> None:
    if not URL:
        die("No `url` input was provided to the PALANIT action.")
    threshold = 999 if FAIL_ON == "never" else SEV.get(FAIL_ON, 3)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "PALANIT-GitHubAction/1.0 (+https://palanit.com)",
    }
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"
    req = urllib.request.Request(
        f"{API}/api/sitecheck",
        data=json.dumps({"url": URL}).encode(),
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        try:
            body = json.load(e)
        except Exception:
            body = {}
        err = body.get("error", "")
        if err == "invalid_key":
            die("PALANIT API key is invalid or revoked — check the `api-key` input / secret.")
        if err == "scope_denied":
            die("This PALANIT API key is not scoped for `sitecheck` — mint one with that scope.")
        if err == "quota_exceeded":
            die(f"PALANIT daily quota reached for plan '{body.get('plan', '?')}' "
                f"({body.get('daily_quota', '?')}/day) — retry tomorrow, raise the quota, or upgrade.")
        if e.code == 429 or err in ("rate_limited", "busy", "domain_cooldown"):
            hint = "" if API_KEY else " Set an `api-key` to lift the per-IP limit and get a daily quota."
            die(f"PALANIT API is rate-limited ({err or e.code}). The free/anonymous tier allows a few "
                f"scans per 10 minutes per source IP — retry later or self-host.{hint}")
        die(f"PALANIT API error (HTTP {e.code} {err}).")
    except Exception as e:  # noqa: BLE001 — surface any transport error to the build log
        die(f"Could not reach the PALANIT API at {API}: {e}")

    if not data.get("ok"):
        die(f"Scan failed: {data.get('error', 'unknown error')}.")
    if not data.get("reachable"):
        die(f"PALANIT could not reach {URL} — a private/internal host, or an off-site redirect, "
            f"is refused by design.")

    grade = data.get("grade", "?")
    score = data.get("score", "?")
    checks = data.get("checks", []) or []
    output("grade", grade)
    output("score", score)

    fails = [c for c in checks if c.get("status") == "fail" and SEV.get(c.get("severity"), 0) >= threshold]
    warns = [c for c in checks if c.get("status") == "warn"]

    for c in fails:
        gh("error", f"[{(c.get('severity') or '').upper()}] {title(c)} — {detail(c)}")
    for c in warns:
        gh("warning", f"{title(c)} — {detail(c)}")

    rows = "\n".join(
        f"| `{(c.get('status') or '').upper()}` | {c.get('severity') or ''} | {title(c)} |"
        for c in (fails + warns)
    ) or "| — | — | No fail/warn findings at or above the threshold |"
    summary(
        f"## PALANIT security scan — {URL}\n\n"
        f"**Grade {grade} ({score}/100)** · {len(fails)} blocking · {len(warns)} warnings\n\n"
        f"| Status | Severity | Check |\n|---|---|---|\n{rows}\n\n"
        f"[Full interactive report ↗](https://palanit.com/security-check)\n"
    )
    print(f"PALANIT: {URL} graded {grade} ({score}/100) — {len(fails)} blocking, {len(warns)} warnings.")

    grade_fail = False
    if MIN_GRADE and MIN_GRADE.lower() != "none":
        gr = GRADES.index(grade) if grade in GRADES else -1
        mr = GRADES.index(MIN_GRADE) if MIN_GRADE in GRADES else -1
        if gr >= 0 and mr >= 0 and gr < mr:
            gh("error", f"Grade {grade} is below the required minimum {MIN_GRADE}.")
            grade_fail = True

    if fails or grade_fail:
        sys.exit(1)
    print("PALANIT gate passed.")


if __name__ == "__main__":
    main()
