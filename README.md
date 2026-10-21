# wazza-tracker

Automated collection of new domains tied to the **Wazza** phishing kit (device code flow, Adobe/DocuSign/OneDrive-themed lures). Wazza was first described by ANY.RUN and later analysed by LevelBlue SpiderLabs. The tracker searches urlscan.io every 6 hours, confirms each new scan by inspecting its requests, and accumulates the results as plain-text IOC lists that detection queries can read.

## How it works

Each run (`wazza_tracker.py`, scheduled with GitHub Actions):

1. **Searches urlscan.io** for scans from the last 30 hours (90 days on the first run):
   - `filename:"wazza-config"`: stable across both observed waves
   - `filename:"klam-kadity"` and `filename:"queltz-narvik"`: the BotID-protected POST on the validation hosts, renamed per wave
   - `filename:"mint-token"`: weak signature, candidates only
   - `domain:<worker>` for every beacon `*.workers.dev` host seen in the last 30 days, as a fallback if the endpoints are renamed
   - optional experimental queries (see `EXPERIMENTAL`)
2. **Opens every new scan** (`/api/v1/result/<uuid>/`) and checks the actual requests.
3. **Confirms or sets aside.** A scan becomes an IOC only if it requested one of the confirming endpoints, or contacted a beacon worker that is already known. Scans that only match `mint-token`, or come from an experimental query, go to `candidates.csv` and never reach the IOC lists.
4. **Writes the results** to `data/` and commits them.
5. **Notifies** via the job summary and, if configured, a Tines webhook.

If the urlscan search API stops short of the reported total (observed: 100 of 138), the script repeats the query with `date:<` set to the day after the oldest result and deduplicates by scan ID.

### Seed data

On every run the script makes sure the IOCs published by LevelBlue SpiderLabs ("Inside Wazza", 2026-10-20) are present in `iocs.csv` with source `levelblue-2026-10-20`: 23 apexes, the preloader host, the two beacon workers, seven final-page workers and seven Google Sites pages. They are vendor-reported and not verified by this tracker. Seeds are never reported as new IOCs. Their `first_seen` is the report date until a scan shows them earlier, in which case `first_seen` moves back to that scan.

## Output (`data/`)

| File | Content |
|---|---|
| `iocs.csv` | Every IOC with type, first seen, last seen, scan ID and source |
| `domains.txt` | Hostnames from confirmed scans (lure, preloader and validation hosts) |
| `apexes.txt` | Registered domains of those hostnames, plus the seeded apexes |
| `workers.txt` | Beacon `*.workers.dev` hosts (the preloader pre-fetches from these) |
| `final_workers.txt` | Long hyphenated `*.workers.dev` hosts that serve the final device code page (seed only) |
| `google_sites.txt` | Google Sites lure pages (`sites.google.com/view/<slug>`) |
| `candidates.csv` | Weak or experimental matches, not confirmed |
| `seen_scans.txt` | Scan IDs already processed (last 5000) |

## Setup

1. Create a repository and copy in `wazza_tracker.py` (repo root) and `.github/workflows/wazza-tracker.yml`.
2. Add repository secrets:
   - `URLSCAN_API_KEY` (a free urlscan.io account is enough)
   - `TINES_WEBHOOK_URL` (optional)
3. Run the workflow once manually (Actions, `workflow_dispatch`) and check that the backfill returns a plausible number of scans.

The script uses only the Python standard library.

### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `URLSCAN_API_KEY` | none | urlscan.io API key (anonymous mode has lower limits) |
| `TINES_WEBHOOK_URL` | none | Receives `{"campaign": "wazza", "new_iocs": [...]}` when new IOCs appear |
| `HOURS` | 30 | Search window for normal runs (overlaps the 6h schedule so a failed run is not lost) |
| `BACKFILL_DAYS` | 90 | Search window for the first run |
| `DATA_DIR` | `data` | Output directory |
| `EXPERIMENTAL` | unset | Comma-separated experimental query names to run, or `all`. The workflow enables `final-page-api-php`. Hits go to `candidates.csv` only |
| `EXPERIMENTAL_MAX_NEW` | 50 | Cap on new scans inspected per experimental query per run (the rest is left for the next run) |

Available experimental queries: `final-page-api-php` (`filename:"api.php"` on `*.workers.dev`, the final page's backend), `botid-uuid` and `tok-param`. The last two are broad and may return many unrelated scans, so enable them one at a time.

## Detection (KQL)

`wazza.kql` matches `DeviceNetworkEvents` against `workers.txt`, `final_workers.txt`, `domains.txt` and `apexes.txt` using `externaldata`. A worker or exact host hit is `high`; an apex-only hit is `medium`. Adjust the user and repository in the URLs.

`externaldata` can only read files that are publicly reachable (or a blob with a SAS token). It will not work against a private repository.

## What the kit looks like (as observed)

This is background for tuning the queries, not a set of verified indicators.

- The lure sits on a random subdomain of a throwaway domain (or in a Google Sites page that embeds it). It requests `/api/wazza-config` and `/api/mint-token`, and pre-fetches from a beacon `*.workers.dev` host. The subdomain must contain one of the prefixes allowed by `wazza-config` (`mine, ask, tun, eln, mkv, luk, orc, znk, ins, dal, hit, buk, hak, swt`), and the same prefix leads the `tg=` parameter.
- The apex domain serves a decoy corporate site after fetching `wazza-config`.
- A separate validation host runs a Next.js app with a bot-protection layer and a rotating POST endpoint. First wave: `check.`, `id.`, `gate.` and `/api/klam-kadity`. Second wave: `portal.`, `hub.`, `svc.` and `/api/queltz-narvik`. A `link.` prefix was also seen in October, which the vendor report does not list.
- The beacon worker changed between waves (`beacon-surge-sync` to `beaconoflinenew.lastfightlink`), together with the POST endpoint.
- The final device code page is served from a long hyphenated `*.workers.dev` host and calls `/api.php?svc=...&action=...`. It sits behind Cloudflare Turnstile, so scanners rarely reach it.

## Limitations

- The tracker only sees what someone has scanned on urlscan.io, and the free plan covers the last 90 days only.
- Apex domains are not verified as attacker-registered. Treat apex-only matches as medium confidence and check registration data (RDAP) for attribution. Workers and exact hosts are the stronger signal.
- If the kit renames `wazza-config` and the validation endpoint and rotates its worker in the same wave, new scans are missed until the signatures in `QUERIES` and `CONFIRM` are updated.
- The `final_workers.txt` list is seed data only. The tracker does not discover new final-page workers on its own, because scanners rarely get that far.
- The experimental queries are not known to be specific to this kit and are off by default, except the narrow `final-page-api-php`.
- Tested against a mocked API. Validate the first live run before relying on it.

## References

- LevelBlue SpiderLabs, "Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365 Accounts" (2026-10-20)
- The Hacker News, "Wazza phishkit targets banking" (2026-10)
