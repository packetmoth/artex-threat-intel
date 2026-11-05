# ARTEX Backdoored Docker Image — Advisory

**Date:** 5 Nov 2026 · **Confidence:** Confirmed (Badbyte / The Hacker News)

A popular ARTEX fork was altered to pull a **backdoored prebuilt Docker image** instead of building from source. The image adds a hidden function to the login code that runs attacker input **as root before the password is checked** — an unauthenticated remote shell. It does not call home; the attacker connects directly to the exposed console.

**Impact:** any host that ran the image is fully compromised (root access to the database, API keys, captured traffic, interception CA key, and token-signing key).

## Image & binary indicators — Confirmed

| Indicator | Type | What it is / why it matters |
|---|---|---|
| `tomicdd/artex:latest` | Docker image | The backdoored image (~7,900 pulls by 3 Nov). |
| `congdonglinux/artex` | Docker image | Copy with identical digests; same backdoor (~33 pulls). |
| `cb85a7206290dc1813e3203e044741054b26c7a7c557c7d9d6d91af20aeb232b` | Image layer SHA-256 | The one layer carrying the malicious binary. Matches even if the image is renamed. |
| `d5070f52262effe216b840711343bff8f2787f39208d887d8dfd9c673f8d1573` | File SHA-256 | The trojanized server binary `/app/artex`. |
| `3aC1db3gGU08O4UHbAt4J` | Web UI build ID | Baked into the backdoored web interface. |

## Backdoor signatures — Confirmed

| Indicator | Type | What it is / why it matters |
|---|---|---|
| `captcha` field on `POST /api/auth/login` | Request content | **Key live signal.** The real login sends only username + password; the backdoor adds a `captcha` field to carry the attacker's command. |
| `verifyCaptcha` function | Code / binary string | Hidden function that runs input as root before auth. Absent from official builds. |
| `…5c0dbd4bec94+dirty`, built without `-trimpath`, version `dev` | Build metadata | Compiled from modified source; official releases are clean, trimmed, and version-tagged. |
| Trigger marker string | — | Withheld by the researcher. Detect via the `captcha` field instead. |

## Suspect — Unconfirmed (carry the ARTEX name; contents not verified)

| Indicator | Type |
|---|---|
| `mianhuatang11/artex`, `autumn26/artex`, `andy1099zz/artex`, `dgddw/artex`, `ylh440104/artex` | Docker images |
| `trhhubsd/ARTEXX` (confirmed — edited to pull the image; removed), `mhtsec/ARTEX`, `RuoJi6/ARTEX` | GitHub repos |

## Detection

1. Alert on any `POST /api/auth/login` whose JSON body contains a `captcha` field.
2. Match running images/containers on the layer digest, binary hash, or web UI build ID above.
3. Check `docker-compose.yml` for `image: tomicdd/artex` / `congdonglinux/artex` instead of a local `build:`.
4. Hunt for exposed consoles on ports `8787`/`8788`.

## Remediation (if a backdoored build ran)

- Assume full compromise.
- Rotate all secrets: database credentials, AI/service API keys, notification/webhook tokens, SMTP passwords, proxy credentials.
- Regenerate the interception CA and `jwt.key` (forges admin tokens).
- Rebuild only from reviewed source and a verified image; never expose the console publicly.
