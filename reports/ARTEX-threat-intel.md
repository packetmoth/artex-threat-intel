# ARTEX — Threat Intelligence & IOC Report

**Date:** 5 November 2026 

## Summary

ARTEX is an open-source, AI-driven autonomous penetration-testing platform. Two distinct threats are tracked here:

1. **A backdoored Docker image** (`tomicdd/artex`) distributed through popular ARTEX forks. It gives an attacker an unauthenticated root shell on any host that runs it. Confirmed by researcher Badbyte (5 Nov 2026).
2. **Real-world attack activity** — ARTEX was used by an unidentified operator against South Korean banks in Oct 2026 (CrowdStrike), leading to data theft.

The two are separate: the backdoor does **not** communicate with an external server. It simply waits for the attacker to connect to an exposed ARTEX console. The campaign infrastructure below belongs to the Korean-bank operator, not the backdoor.

## Key judgements

- Any host that ran `tomicdd/artex` or `congdonglinux/artex` should be treated as **fully compromised** (attacker had root).
- The most reliable *live* way to spot the backdoor is a **`captcha` field in login requests** — the legitimate ARTEX login never sends one.
- Building ARTEX **from reviewed source** (rather than pulling a prebuilt image) avoids the backdoor entirely.

---

## 1. Backdoored Docker image — CONFIRMED

| Indicator | Type | Confidence | What it is / why it matters |
|---|---|---|---|
| `tomicdd/artex:latest` | Docker image | Confirmed | The backdoored image. ~7,900 downloads by 3 Nov. Running it = compromise. |
| `congdonglinux/artex` | Docker image | Confirmed | A copy with identical image digests to the above; same backdoor. ~33 downloads. |
| `cb85a7206290dc1813e3203e044741054b26c7a7c557c7d9d6d91af20aeb232b` | Image layer SHA-256 | Confirmed | Digest of the single image layer that carries the malicious binary. Match it against the layers of any ARTEX image to detect the backdoor **even if the image was renamed or re-tagged**. |
| `d5070f52262effe216b840711343bff8f2787f39208d887d8dfd9c673f8d1573` | File SHA-256 | Confirmed | Hash of the trojanized ARTEX server program (`/app/artex`). Compare against the binary on any running host. |
| `3aC1db3gGU08O4UHbAt4J` | Web UI build ID | Confirmed | Identifier baked into the backdoored web interface. Its presence identifies the malicious build. |

## 2. Backdoor behaviour & code signatures — CONFIRMED

| Indicator | Type | Confidence | What it is / why it matters |
|---|---|---|---|
| `captcha` field on `POST /api/auth/login` | Network / request content | Confirmed | **The key live detection signal.** The genuine ARTEX login sends only a username and password. The backdoored build adds a third field, `captcha`, which is where the attacker hides their command. Seeing this field in login traffic indicates a backdoored instance. |
| `verifyCaptcha` function in the login code | Code / binary string | Confirmed | A hidden function added to the login handler. It runs attacker-supplied input as **root before the password is ever checked** — i.e. an unauthenticated remote shell. Absent from legitimate builds. |
| `Autumn-27/artex v0.3.16-…-5c0dbd4bec94+dirty` | Build metadata | Confirmed | Go build info showing the binary was compiled from **modified** source (`+dirty`). Official releases are clean. |
| Built without `-trimpath` (paths read `/root/ARTEX/...`) | Build artifact | Confirmed | Official builds strip source paths; the backdoored one leaves the attacker's build path visible. |
| Version reports `dev` | Build artifact | Confirmed | Official builds carry a real version tag; the backdoored build reports `dev`. |
| Trigger marker string | — | Withheld | The exact secret string that activates the backdoor was withheld by the researcher to prevent abuse. Detect via the `captcha` field instead. |

## 3. Suspect — UNCONFIRMED (worth checking, not proven malicious)

These are other Docker Hub accounts and GitHub repositories publishing an "artex" image/project. They are flagged **only because they carry the ARTEX name**; their contents have **not** been verified.

| Indicator | Type | Confidence | Note |
|---|---|---|---|
| `mianhuatang11/artex` | Docker image | Unconfirmed | Other publisher; contents not verified |
| `autumn26/artex` | Docker image | Unconfirmed | Other publisher; contents not verified |
| `andy1099zz/artex` | Docker image | Unconfirmed | Other publisher; contents not verified |
| `dgddw/artex` | Docker image | Unconfirmed | Other publisher; contents not verified |
| `ylh440104/artex` | Docker image | Unconfirmed | Other publisher; contents not verified |
| `trhhubsd/ARTEXX` | GitHub repo | Confirmed | The fork whose config was edited to pull the backdoored image. Now removed. |
| `mhtsec/ARTEX` | GitHub repo | Unconfirmed | Removed; previously the most-starred fork |
| `RuoJi6/ARTEX` | GitHub repo | Unconfirmed | Status unknown |

## 4. Korean-bank attack campaign — SEPARATE from the backdoor

Infrastructure and tooling tied to the Oct 2026 attacks on South Korean banks (CrowdStrike / Cloud Security Alliance).

| Indicator | Type | Confidence | What it is |
|---|---|---|---|
| `38.244.50[.]120` | IPv4 | Confirmed | The attacker's ARTEX server used in the campaign. Alert on any traffic to/from it. |
| Hong Kong server (IP not published) | IPv4 | Reported | A second attacker server. |
| ~9 proxy IP addresses (not published) | IPv4 set | Reported | The attacker rotated requests through these, which defeats simple IP blocking. |
| `deepseek-v4.1-flash` | AI model | Confirmed | Primary AI model driving the attack. |
| `GLM-5.3`, `Grok-4.6` | AI model | Confirmed | Additional models used. |

## 5. Host & network artifacts of any ARTEX install

These identify an ARTEX deployment (not necessarily malicious) — useful for finding shadow installs.

| Indicator | Type | What it is |
|---|---|---|
| `artex-enrich/1.0` | HTTP User-Agent | ARTEX's reconnaissance probe. The one ARTEX-specific string seen in inbound attack traffic (but the operator can change it). |
| TCP `8787` | Port | ARTEX web console / API. |
| TCP `8788` | Port | ARTEX's traffic-interception proxy. |
| `/app/artex`, `/app/start.sh` | File path | The server binary and its startup script. |
| `/app/keys/jwt.key` | File path | Login-token signing key. Theft lets an attacker forge admin sessions. |
| `/app/skills/` | File path | Agent capability modules, including offensive ones. |
| `nuclei, httpx, subfinder, katana, ffuf, dalfox, sqlmap, bbot, nmap` | Process names | Scanners bundled in the ARTEX image; execution from a host indicates ARTEX activity. |
| `ARTEX Traffic Capture v1.0.0` | Browser extension | Captures HTTPS traffic and sends it to the ARTEX server. |
| `artex-demo[.]vercel[.]app` | Domain | A public demo instance of one ARTEX fork. |

---

## Detection guidance

1. **Login traffic:** alert on any `POST` to `/api/auth/login` whose JSON body contains a `captcha` field — the backdoor's clearest live signal.
2. **Images & containers:** match running images against the layer digest, the binary hash, or the web UI build ID above; inspect `docker-compose.yml` for `image: tomicdd/artex` or `congdonglinux/artex` instead of a local build.
3. **Exposed consoles:** scan your estate (and the internet, via Shodan/Censys) for ports `8787`/`8788` serving an ARTEX console. These should never be internet-facing.
4. **Inbound attack traffic:** the `artex-enrich/1.0` User-Agent flags ARTEX reconnaissance; back it with behavioural alerts on scanning spikes (sharp rise in requests and in the number of distinct URLs hit from one source).
5. **Campaign infrastructure:** block/alert on `38.244.50[.]120`.

## Remediation (if a backdoored build ran)

- Assume full compromise. The attacker had root and access to the database, AI/service API keys, captured traffic, the interception CA private key, and the token-signing key.
- Rotate every secret: database credentials, all API keys, notification/webhook tokens, SMTP passwords, proxy credentials.
- Regenerate the interception CA and `jwt.key` (it can forge admin tokens).
- Rebuild only from reviewed source and a verified image; never expose the console publicly.

## Sources & confidence

- **Confirmed** = reported by a named researcher/vendor with technical evidence (Badbyte, CrowdStrike, Cloud Security Alliance) or verified in source review of the `BaaRai/ARTEX` fork.
- **Reported** = stated in reporting, not independently verified here.
- **Unconfirmed** = named as related but contents not verified by anyone yet.

Primary sources: Badbyte backdoor analysis (5 Nov 2026); The Hacker News (5 Nov 2026); CrowdStrike and Cloud Security Alliance campaign reporting (Oct 2026).
