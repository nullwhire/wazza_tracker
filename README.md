# wazza_tracker

# wazza-tracker

Automated collection of new domains tied to the **Wazza** phishing kit (device code flow, Adobe-themed lure, first described by ANY.RUN). It searches urlscan.io every 6 hours, confirms each new scan by inspecting its requests, and accumulates the results as plain-text IOC lists that detection queries can read.

## How it works

Each run (`wazza_tracker.py`, scheduled with GitHub Actions):

1. **Searches urlscan.io** for scans from the last 30 hours (90 days on the first run) using:
   - `filename:"wazza-config"` (strong signature)
   - `filename:"mint-token"` (weak signature, candidates only)
   - `domain:<worker>` for every `*.workers.dev` host seen in the last 30 days. This is a fallback in case the kit renames its endpoints.
2. **Opens every new scan** (`/api/v1/result/<uuid>/`) and checks the actual requests.
3. **Confirms or sets aside.** A scan becomes an IOC only if it requested `wazza-config`, or contacted a worker that is already known. Scans that only match `mint-token` go to `candidates.csv` and never reach the IOC lists.
4. **Writes the results** to `data/` and commits them.
5. **Notifies** via the job summary and, if configured, a Tines webhook.

If the urlscan search API stops short of the reported total (observed: 100 of 138), the script repeats the query with `date:<` set to the day after the oldest result and deduplicates by scan ID.

## Output (`data/`)

| File | Content |
|---|---|
| `iocs.csv` | Every IOC with type, first seen, last seen, scan ID and source query |
| `domains.txt` | Landing hostnames from confirmed scans |
| `apexes.txt` | Registered domains of those hostnames |
| `workers.txt` | `*.workers.dev` hosts contacted by confirmed scans |
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
| `EXPERIMENTAL` | unset | Set to `1` to also run the experimental queries (results go to `candidates.csv` only) |

## Detection (KQL)

`wazza.kql` matches `DeviceNetworkEvents` against `workers.txt` and `apexes.txt` using `externaldata`. Replace `<USER>` and `<REPO>` with your own.

`externaldata` can only read files that are publicly reachable (or a blob with a SAS token). It will not work against a private repository.

## What the kit looks like (as observed)

This is background for tuning the queries, not a set of verified indicators.

- The lure page sits on a random subdomain of a throwaway domain (or in a Google Sites page that embeds it). It requests `/api/wazza-config` and `/api/mint-token`, and contacts a `*.workers.dev` host.
- A separate validation host (`check.`, `gate.`, `id.` or `link.` prefix) runs a Next.js app with a bot-protection layer and a rotating POST endpoint name. Those hosts do not request `wazza-config`, so this tracker does not collect them.
- The worker hostname has changed at least once between campaigns, which is why the worker pivot exists.

## Limitations

- The tracker only sees what someone has scanned on urlscan.io, and the free plan covers the last 90 days only.
- Apex domains are not verified as attacker-registered. Some may be third-party domains that were repurposed, so check registration data (RDAP) before blocking on an apex alone. Workers and random subdomains are the stronger signal.
- If the kit renames `wazza-config` and rotates its worker at the same time, new scans are missed until the signature in `QUERIES` is updated.
- The experimental queries (BotID path UUID, `tok=` parameter) are not known to be specific to this kit. They are off by default for that reason.
- Tested against a mocked API. Validate the first live run before relying on it.
