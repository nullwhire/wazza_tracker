#!/usr/bin/env python3
"""urlscan.io tracker for the Wazza phishing kit (device code, Adobe lure, Next/Vercel + workers.dev).

Runs every 6 hours (GitHub Actions). Each run:
  1. searches for new scans by signature (filename wazza-config / mint-token)
     and pivots on the workers.dev hosts already known (survives endpoint renames)
  2. opens each new scan (/api/v1/result/) and confirms the signature in its requests
  3. accumulates IOCs in data/ and reports new ones (Tines webhook optional)

Environment:
  URLSCAN_API_KEY     urlscan API key (secret)
  TINES_WEBHOOK_URL   optional, receives JSON with the new IOCs
  HOURS               normal search window, default 30 (covers one failed run)
  BACKFILL_DAYS       window for the first run (no state), default 90
  DATA_DIR            default ./data
  EXPERIMENTAL        set to 1 to also run the experimental queries
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

# on=False: experimental, not tested as reliable pivots. Their hits only go to candidates.csv.
QUERIES = [
    {"name": "wazza-config", "q": 'filename:"wazza-config"', "on": True},
    {"name": "mint-token", "q": 'filename:"mint-token"', "on": True},
    {"name": "botid-uuid", "q": "page.url:*149e9513-01fa-4fb0-aad4-566afd725d1b*", "on": False},
    {"name": "tok-param", "q": "page.url:*tok=179*", "on": False},
]
CONFIRM = "wazza-config"          # last path segment that confirms the kit
CANDIDATE = {"mint-token"}        # weak signal, never enters the IOC lists
EXCLUDE_APEX = {"google.com", "workers.dev", "vercel.app", "cloudflare.com",
                "googleapis.com", "gstatic.com"}
TWO_LABEL = {"co.uk", "org.uk", "com.br", "com.au", "co.jp"}
WORKER_DAYS = 30                  # pivot on workers seen in the last N days
WORKER_MAX = 10


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
    clause = f"date:>now-{BACKFILL}d" if first else f"date:>now-{HOURS}h"
    log("first run (backfill)" if first else "normal run", "|", clause,
        "| key:", "yes" if KEY else "NO")

    iocs = {}
    if os.path.exists(p_iocs):
        with open(p_iocs, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                iocs[(r["type"], r["value"])] = r
    known_workers = {v for (t, v) in iocs if t == "worker"}
    cutoff = (date.today() - timedelta(days=WORKER_DAYS)).isoformat()
    recent = sorted((r for (t, _), r in iocs.items() if t == "worker" and r["last_seen"][:10] >= cutoff),
                    key=lambda r: r["last_seen"], reverse=True)[:WORKER_MAX]

    queries = [(x["name"], x["q"]) for x in QUERIES if x["on"]]
    queries += [("worker:" + r["value"], f"domain:{r['value']}") for r in recent]
    experimental = [(x["name"], x["q"]) for x in QUERIES if not x["on"]]
    experimental_names = {n for n, _ in experimental}
    queries += experimental if os.environ.get("EXPERIMENTAL") else []

    todo = {}
    for name, q in queries:
        try:
            rs = search_all(f"({q}) AND {clause}")
        except Exception as e:
            log(f"[{name}] error: {e}")
            continue
        new = [r for r in rs if r["_id"] not in seen]
        log(f"[{name}] {len(rs)} scans, {len(new)} new")
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
        confirmed = (CONFIRM in s["names"]
                     or (s["workers"] & known_workers and qname not in experimental_names))
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
            elif s["time"] > iocs[k]["last_seen"]:
                iocs[k]["last_seen"] = s["time"]

    with open(p_iocs, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["type", "value", "first_seen", "last_seen", "scan_id", "source"])
        w.writeheader()
        w.writerows(sorted(iocs.values(), key=lambda r: (r["type"], r["first_seen"])))
    for fname, t in (("domains.txt", "domain"), ("apexes.txt", "apex"),
                     ("workers.txt", "worker"), ("google_sites.txt", "gsite")):
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
