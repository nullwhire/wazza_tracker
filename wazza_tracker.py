#!/usr/bin/env python3
"""urlscan.io tracker for the Wazza phishing kit (device code, Adobe lure, Next/Vercel + workers.dev).

Runs every 6 hours (GitHub Actions). Each run:
  1. searches for new scans by signature: filename wazza-config (stable across waves),
     klam-kadity / queltz-narvik (BotID-protected POST on the validation hosts, renamed
     per wave), mint-token (weak, candidates only), plus a pivot on the beacon workers.dev
     hosts already known (survives endpoint renames)
  2. opens each new scan (/api/v1/result/) and confirms the signature in its requests
  3. accumulates IOCs in data/ and reports new ones (Tines webhook optional)
  4. seeds data/ with the IOCs published by LevelBlue SpiderLabs (2026-10-20); seeds are
     never reported as new, and first_seen moves back if a scan shows them earlier

Environment:
  URLSCAN_API_KEY     urlscan API key (secret)
  TINES_WEBHOOK_URL   optional, receives JSON with the new IOCs
  HOURS               normal search window, default 30 (covers one failed run)
  BACKFILL_DAYS       window for the first run (no state), default 90
  DATA_DIR            default ./data
  EXPERIMENTAL        comma-separated names of experimental queries to run (or "all"),
                      e.g. final-page-api-php. Hits go to candidates.csv only.
  EXPERIMENTAL_MAX_NEW  cap of new scans inspected per experimental query per run, default 50
"""
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, timedelta

SEARCH = "https://urlscan.io/api/v1/search/"
RESULT = "https://urlscan.io/api/v1/result/{}/"
DATA = os.environ.get("DATA_DIR", "data")
HOURS = int(os.environ.get("HOURS", "30"))
BACKFILL = int(os.environ.get("BACKFILL_DAYS", "90"))
KEY = os.environ.get("URLSCAN_API_KEY")
EXPERIMENTAL = {x.strip() for x in os.environ.get("EXPERIMENTAL", "").split(",") if x.strip()}
EXP_CAP = int(os.environ.get("EXPERIMENTAL_MAX_NEW", "50"))

# on=False: experimental, not tested as reliable pivots. Their hits only go to candidates.csv.
QUERIES = [
    {"name": "wazza-config", "q": 'filename:"wazza-config"', "on": True},
    {"name": "mint-token", "q": 'filename:"mint-token"', "on": True},
    {"name": "klam-kadity", "q": 'filename:"klam-kadity"', "on": True},
    {"name": "queltz-narvik", "q": 'filename:"queltz-narvik"', "on": True},
    {"name": "final-page-api-php", "q": 'filename:"api.php" AND domain:*.workers.dev', "on": False},
    {"name": "botid-uuid", "q": "page.url:*149e9513-01fa-4fb0-aad4-566afd725d1b*", "on": False},
    {"name": "tok-param", "q": "page.url:*tok=179*", "on": False},
]
# Last path segments that confirm the kit. wazza-config is stable across waves; the other two
# are the BotID-protected POST on the validation hosts and rotate per wave (LevelBlue, 2026-10-20).
CONFIRM = {"wazza-config", "klam-kadity", "queltz-narvik"}
CANDIDATE = {"mint-token"}        # weak signal, never enters the IOC lists
EXCLUDE_APEX = {"google.com", "workers.dev", "vercel.app", "cloudflare.com",
                "googleapis.com", "gstatic.com"}
TWO_LABEL = {"co.uk", "org.uk", "com.br", "com.au", "co.jp"}
WORKER_DAYS = 30                  # pivot on workers seen in the last N days
WORKER_MAX = 10


# IOCs published in "Inside Wazza" (LevelBlue SpiderLabs, 2026-10-20). Vendor-reported, not
# verified by this tracker. Final-page workers are kept apart: scanners rarely reach them.
SEED_SRC = "levelblue-2026-10-20"
SEED_TS = "2026-10-20T00:00:00.000Z"
SEED = {
    "apex": sorted({
        "beton-beton.eu", "bike-msca.eu", "bodi-project.eu", "bruoth-family.eu", "cardamomo.eu",
        "coppietersrecherche.eu", "diabetesnet.eu", "dymowski.eu", "euniverza.eu", "hutspotmaken.eu",
        "illuminatedminds.eu", "jetcapital.eu", "languagesforwork.eu", "lesbolides.eu", "mdiament.eu",
        "nbi-training.eu", "nellarmonia.eu", "originalpizza.eu", "polskaprezydencjacsr.eu",
        "robologic.eu", "safetystock.eu", "electroloys.com", "hacsg.com"}),
    "domain": ["fgwhjmdaurspxvznk.hutspotmaken.eu"],
    "worker": ["beacon-surge-sync.beacon-surge-sync.workers.dev",
               "beaconoflinenew.lastfightlink.workers.dev"],
    "worker_final": [
        "dv0psh-purv3w-azfn-b2c0-msauth3-m365svc-s3ntln-4zrfn3x-cntnrx.workers.dev",
        "ssosvc-m365s-kvl-dv0pshb-s3ntln-c0mply-4zrmonx-apimgwx-evnthb.workers.dev",
        "wndws-pip3ln-sql3-waf3-purv3-gdprsx-dfn-azfn-appsvc-0ffapx.workers.dev",
        "purv3w3-t3ms4pp-certs-intun3-sbussvx-4zredg-siemsv-pip3ln-0ffc3.workers.dev",
        "c5id-pc17-fffoub1-bul3-ahv1-r00kubt.ondrv-pwrbi3-s3ntln-quesvxs-l0gsvx-entr-m365s-cmplncx-ehubn.workers.dev",
        "d3m9a-goo2ns-wx0g-jzhuc2-t9r2b9i.dvps-azbl-fnapp-trc3svc-synpx-quesvxs-purv3-siemsvx-cmplncx.workers.dev",
        "unhf69e-e0ppo-l0qoo-a12bcfj-ig1sa4v.wndws-pip3ln-sql3-waf3-purv3-gdprsx-dfn-azfn-appsvc-0ffapx.workers.dev",
    ],
    "gsite": ["sites.google.com/view/" + x for x in (
        "hgfdsqazxcvhjoswwqq", "adobe-docus", "miticabo", "ctfvygbuhgyftvbgyfpoiuytrftgyh",
        "kjvcfdswqazxcfvghjoplkjmnbvcf", "securespdf", "onwajuly")],
}


def seed(iocs):
    n = 0
    for t, vals in SEED.items():
        for v in vals:
            if (t, v) not in iocs:
                iocs[(t, v)] = {"type": t, "value": v, "first_seen": SEED_TS, "last_seen": SEED_TS,
                                "scan_id": "", "source": SEED_SRC}
                n += 1
    return n


def window_clause(hours):
    """Whole days use the d unit (the form already used by the backfill), otherwise hours."""
    if hours >= 24 and hours % 24 == 0:
        return f"date:>now-{hours // 24}d"
    return f"date:>now-{hours}h"


def log(*a):
    print(*a, file=sys.stderr)


def get(url, allow_404=False, retries=5):
    headers = {"User-Agent": "wazza-tracker/1.0"}
    if KEY:
        headers["API-Key"] = KEY
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = 10 * (attempt + 1)
                log(f"429, waiting {wait}s")
                time.sleep(wait)
                continue
            if e.code in (404, 410) and allow_404:
                return None
            raise
    raise RuntimeError("too many 429 responses")


def search_all(q, size=100):
    """All scans for q. If the API stops short of the total (seen: 100 of 138),
    repeat with date:< set to the day after the oldest result and dedupe by id."""
    got, ids, cur = [], set(), q
    for _ in range(8):
        pass_ids, after, total = set(), None, None
        while True:
            params = {"q": cur, "size": size}
            if after:
                params["search_after"] = after
            d = get(SEARCH + "?" + urllib.parse.urlencode(params))
            batch = d.get("results", [])
            total = d.get("total")
            for r in batch:
                pass_ids.add(r["_id"])
                if r["_id"] not in ids:
                    ids.add(r["_id"])
                    got.append(r)
            if not d.get("has_more") or not batch or not batch[-1].get("sort"):
                break
            after = ",".join(str(x) for x in batch[-1]["sort"])
            time.sleep(2)
        if not isinstance(total, int) or len(pass_ids) >= total or not pass_ids:
            break
        oldest = min(r["task"]["time"] for r in got)[:10]
        nxt = (date.fromisoformat(oldest) + timedelta(days=1)).isoformat()
        new_q = f"({q}) AND date:<{nxt}"
        if new_q == cur:
            log("WARNING: no progress on this page, stopping")
            break
        cur = new_q
        time.sleep(2)
    return got


def apex(host):
    p = host.split(".")
    if len(p) >= 3 and ".".join(p[-2:]) in TWO_LABEL:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def inspect(res):
    names, workers = set(), set()
    reqs = (res.get("data") or {}).get("requests") or []
    urls = [(((e.get("request") or {}).get("request")) or {}).get("url", "") for e in reqs]
    urls += (res.get("lists") or {}).get("urls") or []
    for u in urls:
        if not u:
            continue
        p = urllib.parse.urlparse(u)
        host = (p.hostname or "").lower()
        if host.endswith(".workers.dev"):
            workers.add(host)
        seg = p.path.rstrip("/").rsplit("/", 1)[-1].lower()
        if seg:
            names.add(seg)
    page, task = res.get("page") or {}, res.get("task") or {}
    return {"domain": (page.get("domain") or "").lower(),
            "url": page.get("url") or task.get("url") or "",
            "time": task.get("time", ""), "names": names, "workers": workers}


def load_lines(path):
    try:
        with open(path, encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


def main():
    os.makedirs(DATA, exist_ok=True)
    p_seen = os.path.join(DATA, "seen_scans.txt")
    p_iocs = os.path.join(DATA, "iocs.csv")
    p_cand = os.path.join(DATA, "candidates.csv")
    seen = set(load_lines(p_seen))
    first = not seen
    clause = f"date:>now-{BACKFILL}d" if first else window_clause(HOURS)
    log("first run (backfill)" if first else "normal run", "|", clause,
        "| key:", "yes" if KEY else "NO")

    iocs = {}
    if os.path.exists(p_iocs):
        with open(p_iocs, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                iocs[(r["type"], r["value"])] = r
    seeded = seed(iocs)
    if seeded:
        log(f"seeded {seeded} IOCs from {SEED_SRC}")
    known_workers = {v for (t, v) in iocs if t == "worker"}
    cutoff = (date.today() - timedelta(days=WORKER_DAYS)).isoformat()
    recent = sorted((r for (t, _), r in iocs.items() if t == "worker" and r["last_seen"][:10] >= cutoff),
                    key=lambda r: r["last_seen"], reverse=True)[:WORKER_MAX]

    queries = [(x["name"], x["q"]) for x in QUERIES if x["on"]]
    queries += [("worker:" + r["value"], f"domain:{r['value']}") for r in recent]
    experimental_names = {x["name"] for x in QUERIES if not x["on"]}
    queries += [(x["name"], x["q"]) for x in QUERIES
                if not x["on"] and ("all" in EXPERIMENTAL or x["name"] in EXPERIMENTAL)]

    todo = {}
    for name, q in queries:
        try:
            rs = search_all(f"({q}) AND {clause}")
        except Exception as e:
            log(f"[{name}] error: {e}")
            continue
        new = [r for r in rs if r["_id"] not in seen]
        log(f"[{name}] {len(rs)} scans, {len(new)} new")
        if name in experimental_names and len(new) > EXP_CAP:
            log(f"[{name}] capped at {EXP_CAP} new scans, the rest is left for the next run")
            new = new[:EXP_CAP]
        for r in new:
            todo.setdefault(r["_id"], name)
        time.sleep(2)

    now_new, cands = [], []
    for sid, qname in todo.items():
        try:
            res = get(RESULT.format(sid), allow_404=True)
        except Exception as e:
            log(f"{sid}: error {e}, left for the next run")
            continue
        seen.add(sid)
        time.sleep(1)
        if res is None:
            continue
        s = inspect(res)
        confirmed = bool(CONFIRM & s["names"]) or bool(
            s["workers"] & known_workers and qname not in experimental_names)
        if not confirmed:
            if (s["names"] & CANDIDATE) or qname in experimental_names:
                cands.append({"scan_id": sid, "time": s["time"], "domain": s["domain"],
                              "url": s["url"][:200], "names": " ".join(sorted(s["names"] & CANDIDATE)),
                              "workers": " ".join(sorted(s["workers"])), "query": qname})
            continue
        found = []
        d = s["domain"]
        if d == "sites.google.com":
            parts = urllib.parse.urlparse(s["url"]).path.strip("/").split("/")
            if len(parts) >= 2 and parts[0] == "view":
                found.append(("gsite", "sites.google.com/view/" + parts[1]))
        elif d and apex(d) not in EXCLUDE_APEX:
            found += [("domain", d), ("apex", apex(d))]
        found += [("worker", w) for w in s["workers"]]
        for t, v in found:
            k = (t, v)
            if k not in iocs:
                iocs[k] = {"type": t, "value": v, "first_seen": s["time"], "last_seen": s["time"],
                           "scan_id": sid, "source": qname}
                now_new.append(iocs[k])
            else:
                if s["time"] > iocs[k]["last_seen"]:
                    iocs[k]["last_seen"] = s["time"]
                if s["time"] and s["time"] < iocs[k]["first_seen"]:
                    iocs[k]["first_seen"] = s["time"]
                    iocs[k]["scan_id"] = sid

    with open(p_iocs, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["type", "value", "first_seen", "last_seen", "scan_id", "source"])
        w.writeheader()
        w.writerows(sorted(iocs.values(), key=lambda r: (r["type"], r["first_seen"])))
    for fname, t in (("domains.txt", "domain"), ("apexes.txt", "apex"),
                     ("workers.txt", "worker"), ("final_workers.txt", "worker_final"),
                     ("google_sites.txt", "gsite")):
        with open(os.path.join(DATA, fname), "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(v for (tt, v) in iocs if tt == t)) + "\n")
    if cands:
        newfile = not os.path.exists(p_cand)
        with open(p_cand, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(cands[0].keys()))
            if newfile:
                w.writeheader()
            w.writerows(cands)
    with open(p_seen, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(seen)[-5000:]) + "\n")

    lines = [f"Wazza tracker: {len(todo)} new scans, {len(now_new)} new IOCs, {len(cands)} candidates"]
    lines += [f"  NEW {r['type']:7s} {r['value']}  ({r['first_seen'][:10]}, {r['source']})" for r in now_new]
    print("\n".join(lines))
    summ = os.environ.get("GITHUB_STEP_SUMMARY")
    if summ:
        with open(summ, "a", encoding="utf-8") as f:
            f.write("```\n" + "\n".join(lines) + "\n```\n")
    hook = os.environ.get("TINES_WEBHOOK_URL")
    if hook and now_new:
        body = json.dumps({"campaign": "wazza", "new_iocs": now_new}).encode()
        try:
            urllib.request.urlopen(urllib.request.Request(
                hook, data=body, headers={"Content-Type": "application/json"}), timeout=30)
        except Exception as e:
            log(f"webhook failed: {e}")


if __name__ == "__main__":
    main()
