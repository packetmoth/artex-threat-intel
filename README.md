# ARTEX — Threat Intelligence

Indicators and detections for the **ARTEX** AI-driven autonomous penetration-testing platform.

Two threats are tracked:

1. **Backdoored Docker image** (`tomicdd/artex`) — gives an attacker an unauthenticated root shell on any host that runs it. Confirmed by researcher Badbyte, 5 Nov 2026.
2. **Real-world attack campaign** — ARTEX used against South Korean banks, Oct 2026 (CrowdStrike), resulting in data theft. Separate from the backdoor.

> The backdoor does **not** call home. It waits for the attacker to connect to an exposed ARTEX console. The campaign infrastructure is a different operator.

## Key judgements

- Any host that ran `tomicdd/artex` or `congdonglinux/artex` should be treated as **fully compromised**.
- Best live detection: a **`captcha` field in `POST /api/auth/login`** — the legitimate login never sends one.
- Building ARTEX **from reviewed source** avoids the backdoor entirely.

## Contents

| Path | What it is |
|---|---|
| `reports/ARTEX-threat-intel.md` | Full narrative report (all indicators, explained) |
| `iocs/docker-image-backdoor.md` | Focused advisory for the backdoored image |
| `iocs/full-iocs.csv` | All indicators, machine-ingestible |
| `iocs/docker-image.csv` | Docker-image subset, machine-ingestible |
| `detections/artex_backdoor.yar` | YARA — backdoored binary/image |
| `detections/artex_backdoor.semgrep.yaml` | Semgrep — backdoor in Go source |
| `detections/artex_detections.sigma.yaml` | Sigma — host/network/login detections |

## Confidence legend

- **Confirmed** — named researcher/vendor with technical evidence, or verified in source review.
- **Reported** — stated in reporting, not independently verified.
- **Unconfirmed** — named as related, contents not verified by anyone yet.

## Sources

Badbyte backdoor analysis (5 Nov 2026); The Hacker News (5 Nov 2026); CrowdStrike & Cloud Security Alliance campaign reporting (Oct 2026); source review of the `BaaRai/ARTEX` fork.

_Last updated: 2026-11-05 · TLP:AMBER_
