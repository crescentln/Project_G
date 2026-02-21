# Self-Owned Ruleset Pipeline

This repository builds your own ruleset assets for both OpenClash and Surge.

It uses the same production pattern as major public projects:
1. fetch upstream datasets,
2. normalize into one internal rule model,
3. deduplicate and report cross-category overlaps,
4. export multi-client formats,
5. auto-update with GitHub Actions.

## What Is Different

- No dependency on Sukka/Quixotic hosted output files.
- All categories and sources are controlled in:
  - `ruleset/config/sources.json`
- Recommended action (DIRECT/PROXY/REJECT) per category is controlled in:
  - `ruleset/config/policy_map.json`
- Category content is controlled in:
  - `ruleset/manual/categories/*.txt`
- Official machine-readable sources are used where available:
  - IANA special-use registries
  - APNIC delegated data
  - Telegram official CIDR feed
  - Cloudflare/AWS/GCP official IP ranges

## Output Layout

Generated under `ruleset/dist/`:

- `surge/<category>.list` (classical rules)
- `surge/non_ip/<category>.list` (non-IP split)
- `surge/ip/<category>.list` (IP split)
- `surge/domainset/<category>.conf` (DOMAIN-SET compatible)
- `openclash/<category>.yaml` (classical provider)
- `openclash/non_ip/<category>.yaml` (non-IP split)
- `openclash/ip/<category>.yaml` (IP split in classical form)
- `openclash/domainset/<category>.txt` (domainset text)
- `openclash/ipcidr/<category>.txt` (CIDR-only text)
- `compat/Clash/non_ip/<category>.txt` (Sukka-style clash classical text)
- `compat/Clash/ip/<category>.txt` (Sukka-style clash IP text)
- `compat/Clash/domainset/<category>.txt` (Sukka-style clash domainset text)
- `compat/List/non_ip/<category>.conf` (Sukka-style surge classical text)
- `compat/List/ip/<category>.conf` (Sukka-style surge IP text)
- `compat/List/domainset/<category>.conf` (Sukka-style surge domainset text)
- `index.json` (build manifest)
- `conflicts.json` (cross-category overlaps)
- `policy_reference.json` (machine-readable policy map)
- `policy_reference.md` (human-readable policy reference)
- `meta/<category>.json` (per-category action/paths/source detail)

## Build

Online:

```bash
python3 ruleset/scripts/build_rulesets.py
```

Offline (cache only):

```bash
python3 ruleset/scripts/build_rulesets.py --offline
```

Validate generated format:

```bash
python3 ruleset/scripts/validate_rulesets.py
```

## Auto Update

Workflow file:

- `.github/workflows/ruleset-update.yml`

Schedule:

- every 6 hours (`cron: 17 */6 * * *`)

Behavior:

1. Build rulesets.
2. Commit `ruleset/dist` only if changed.

## Migration

Your existing OpenClash/Surge names are mapped in:

- `ruleset/MAPPING.md`
