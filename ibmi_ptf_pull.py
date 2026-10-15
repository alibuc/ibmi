#!/usr/bin/env python3
#
# Copyright (c) 2026, Informed Technology Pty Ltd as trustee for the AB Trust
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Pull IBM security-bulletin PTF numbers and download links for a given IBM i release.

Discovery uses IBM's bulletin JSON API (the one behind
https://www.ibm.com/support/pages/bulletin/search):

    /support/pages/securityapp/api/site/datalist

Bulletin bodies are server-rendered at /support/pages/node/<nid>, so the PTF
tables can be parsed straight out of the HTML - no browser required.

API LIMITATION
    Returns only the ~1000 most recently published records. offset= is ignored, 
    and limit= above 1000 has no effect.
    IBM publishes enough bulletins that 1000 records could span a couple of days,
    so this script can't reach arbitrary historical dates on its own.

    Mitigation: every run merges the current snapshot into a local index cache
    (--cache-dir). Run this daily (cron) and the cache accumulates history that
    outlives the API window. --list-dates shows what the cache currently holds.

Usage examples
    # everything IBM i published on one day, every release in the bulletins
    ./ibmi_ptf_pull.py --date 2026-08-11

    # same, but restrict output to a single release
    ./ibmi_ptf_pull.py --date 2026-08-11 --release 7.5

    # restrict to specific CVEs (file with one CVE ID per line, or a TSV
    # containing them - any CVE-looking token on the line is picked up)
    ./ibmi_ptf_pull.py --cve-file list_of_cve

    # specific bulletins by node id, skipping discovery entirely
    ./ibmi_ptf_pull.py --nid 7283359 --nid 7283281

    # what does the cache know about?
    ./ibmi_ptf_pull.py --list-dates
"""

from __future__ import annotations

import argparse
import collections
import csv
import gzip
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = "https://www.ibm.com"
DATALIST = BASE + "/support/pages/securityapp/api/site/datalist?offset=0&limit=1000"
NODE_URL = BASE + "/support/pages/node/{nid}"

# IBM rejects unrecognised clients, so present a normal browser UA. 
# Override with --user-agent if you need to identify differently.
DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

# Index + bulletin-HTML cache. Persists across runs so history outlives IBM's
# ~1000-record API window. Override with --cache-dir or $IBM_PTF_CACHE_DIR.
DEFAULT_CACHE_DIR = os.path.expanduser(
    os.environ.get("IBM_PTF_CACHE_DIR", "~/.cache/ibm_ptf_pull"))

# ANSI colors, applied only when the target stream is a color-capable TTY.
ANSI = {"grey": "\033[2m", "green": "\033[32m",
        "red": "\033[31m", "orange": "\033[38;5;208m", "yellow": "\033[33m"}
RESET = "\033[0m"


def _color_ok(stream) -> bool:
    return (getattr(stream, "isatty", lambda: False)()
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM") != "dumb")


def paint(text: str, color: str, stream) -> str:
    code = ANSI.get(color)
    return f"{code}{text}{RESET}" if code and _color_ok(stream) else text

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
RELEASE_RE = re.compile(r"^\d\.\d$")           # 7.3 / 7.4 / 7.5 / 7.6
PTF_RE = re.compile(r"\b[A-Z]{2}\d{5}\b")      # SJ10961, MJ10909, SI/MF...
LPP_RE = re.compile(r"\b\d{4}-[A-Z0-9]{3}\b")  # 5770-SS1, 5770-DBM, 5770-999


# --------------------------------------------------------------------------- http


def fetch(url: str, ua: str, timeout: int = 60, retries: int = 3,
          backoff: float = 2.0) -> bytes:
    """GET a URL with retries. Returns decoded (gunzipped) body bytes."""
    last = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(
            url,
            headers={"User-Agent": ua, "Accept-Encoding": "gzip",
                     "Accept": "text/html,application/json;q=0.9,*/*;q=0.8"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    body = gzip.decompress(body)
                return body
        except urllib.error.HTTPError as exc:
            # 4xx are permanent (bad/removed nid, auth) - don't waste retries.
            # (HTTPError is a URLError subclass, so this must be caught first.)
            if 400 <= exc.code < 500:
                raise RuntimeError(f"HTTP {exc.code} for {url}") from exc
            last = exc
            if attempt < retries:
                time.sleep(backoff * attempt)
        except (urllib.error.URLError, OSError) as exc:
            last = exc
            if attempt < retries:
                time.sleep(backoff * attempt)
    raise RuntimeError(f"failed after {retries} attempts: {url} ({last})")


# ------------------------------------------------------------------- discovery


def load_index(cache_dir: str) -> dict:
    path = os.path.join(cache_dir, "index.json")
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            # Corrupt/truncated cache (e.g. interrupted write before atomic
            # replace was added). Start fresh; next save_index overwrites it.
            print(f"[warn] ignoring unreadable index {path}: {exc}",
                  file=sys.stderr)
    return {}


def save_index(cache_dir: str, index: dict) -> None:
    os.makedirs(cache_dir, exist_ok=True)
    path = os.path.join(cache_dir, "index.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def refresh_index(cache_dir: str, ua: str, verbose: bool = True) -> dict:
    """Merge the current datalist snapshot into the on-disk index and return it."""
    index = load_index(cache_dir)
    before = len(index)
    raw = json.loads(fetch(DATALIST, ua))
    records = raw.get("results", {}).get("top_records", [])
    for rec in records:
        cve = (rec.get("field_cve_id") or "").strip()
        nid = (rec.get("nid") or "").strip()
        if not nid:
            continue
        product = (rec.get("field_product") or "").strip()
        # Key on product too: one bulletin can list the same CVE under several
        # product names (e.g. both "IBM Db2 Mirror for i" and "IBM i"), and a
        # nid|cve key would silently overwrite the product field.
        index[f"{nid}|{cve}|{product}"] = {
            "nid": nid,
            "cve": cve,
            "title": (rec.get("title") or "").strip(),
            "product": product,
            "severity": (rec.get("field_cvss_base_score") or "").strip(),
            "pub_date": (rec.get("field_pub_date") or "").strip()[:10],
        }
    save_index(cache_dir, index)
    if verbose:
        span = sorted({v["pub_date"] for v in index.values() if v["pub_date"]})
        print(paint(f"[index] api snapshot: {len(records)} records; "
                    f"cache {before} -> {len(index)} entries"
                    + (f"; span {span[0]}..{span[-1]}" if span else ""),
                    "grey", sys.stderr), file=sys.stderr)
        if len(records) >= 1000:
            print(paint("[index] NOTE: API returned its 1000-record cap - older "
                        "bulletins are only available from cache.", "grey",
                        sys.stderr), file=sys.stderr)
    return index


def select(index: dict, product: str | None, dates: set[str] | None,
           since: str | None, until: str | None,
           cves: set[str] | None) -> list[dict]:
    """Filter index entries. All criteria are ANDed; None means 'no constraint'."""
    out = []
    for entry in index.values():
        if product and entry["product"].strip().lower() != product.strip().lower():
            continue
        if dates and entry["pub_date"] not in dates:
            continue
        if since and (not entry["pub_date"] or entry["pub_date"] < since):
            continue
        if until and (not entry["pub_date"] or entry["pub_date"] > until):
            continue
        if cves and entry["cve"] not in cves:
            continue
        out.append(entry)
    # One CVE can match under several product names; keep one row per (nid, cve)
    # so a CVE is never counted twice.
    seen, deduped = set(), []
    for entry in out:
        key = (entry["nid"], entry["cve"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped


# --------------------------------------------------------------------- parsing


def _cells(row_html: str) -> list[tuple[str, str | None]]:
    """Return [(cell text, first href in cell)] for one <tr>."""
    cells = []
    for m in re.finditer(r"(?is)<t[dh]\b[^>]*>(.*?)</t[dh]>", row_html):
        inner = m.group(1)
        href = re.search(r'href="([^"]+)"', inner)
        text = re.sub(r"(?s)<[^>]+>", " ", inner)
        text = re.sub(r"\s+", " ", html.unescape(text)).strip()
        cells.append((text, html.unescape(href.group(1)) if href else None))
    return cells


def parse_bulletin(nid: str, page: str) -> dict:
    """Extract title, CVEs, affected releases and release->PTF rows from a bulletin."""
    title = ""
    m = re.search(r"(?is)<title>(.*?)</title>", page)
    if m:
        title = re.sub(r"\s*-\s*IBM Support\s*$", "", html.unescape(m.group(1))).strip()
        title = re.sub(r"^Security Bulletin:\s*", "", title)

    fixes, affected = [], set()
    for table in re.findall(r"(?is)<table.*?</table>", page):
        rows = [_cells(r) for r in re.findall(r"(?is)<tr\b[^>]*>(.*?)</tr>", table)]
        flat = " ".join(c[0] for row in rows for c in row)
        is_fix_table = "ptf" in flat.lower()

        # LPP declared once in the header (e.g. "5770-SS1 PTF Numbers")
        header_lpp = None
        for row in rows:
            joined = " ".join(c[0] for c in row)
            if re.search(r"ptf", joined, re.IGNORECASE):
                found = LPP_RE.search(joined)
                if found:
                    header_lpp = found.group(0)
                    break

        for row in rows:
            if not row or not RELEASE_RE.match(row[0][0].strip()):
                continue
            release = row[0][0].strip()
            if not is_fix_table:
                affected.add(release)       # "Affected Product(s)" table
                continue
            affected.add(release)
            joined = " ".join(c[0] for c in row[1:])
            ptfs = PTF_RE.findall(joined)
            # a row may carry its own LPP, which wins over the header's
            row_lpp = LPP_RE.search(joined)
            link = None
            for _, href in row[1:]:
                if href and "fix-information" in href:
                    link = href
                    break
            if link is None:
                for text, href in row[1:]:
                    cand = href or text
                    if cand and cand.startswith("http"):
                        link = cand
                        break
            if not ptfs and not link:
                continue
            fixes.append({
                "release": release,
                "ptfs": ptfs,
                "lpp": (row_lpp.group(0) if row_lpp else header_lpp) or "",
                "link": link or "",
                "note": "" if ptfs else joined[:120],
            })

    return {
        "nid": nid,
        "url": NODE_URL.format(nid=nid),
        "title": title,
        "cves": sorted(set(CVE_RE.findall(page))),
        "affected_releases": sorted(affected),
        "fixes": fixes,
    }


def get_bulletin(nid: str, ua: str, cache_dir: str, refresh: bool,
                 delay: float) -> dict:
    """Fetch (or read cached) bulletin HTML and parse it."""
    html_dir = os.path.join(cache_dir, "nodes")
    os.makedirs(html_dir, exist_ok=True)
    path = os.path.join(html_dir, f"{nid}.html")
    if refresh or not os.path.exists(path):
        body = fetch(NODE_URL.format(nid=nid), ua)
        with open(path, "wb") as fh:
            fh.write(body)
        if delay:
            time.sleep(delay)
        # decode the body we already have rather than reading it back off disk
        page = body.decode("utf-8", errors="replace")
    else:
        with open(path, encoding="utf-8", errors="replace") as fh:
            page = fh.read()
    return parse_bulletin(nid, page)


# ---------------------------------------------------------------------- output


def cve_sort_key(cve: str):
    m = re.match(r"CVE-(\d{4})-(\d+)$", cve)
    return (int(m.group(1)), int(m.group(2))) if m else (9999, 0)


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def print_severity_summary(selected: list[dict], stream=sys.stdout) -> None:
    """Print a count of selected CVEs per severity bucket, Critical -> Low."""
    
    if not getattr(stream, "isatty", lambda: False)():
        return  # don't print the summary if output is redirected to a file

    print("\n--------------------------------", file=stream)
    print("Severity summary (All releases):", file=stream)

    order = ("Critical", "High", "Medium", "Low")
    sev_color = {"Critical": "red", "High": "orange", "Medium": "yellow", "Low": ""}
    counts = collections.Counter(
        e["severity"].strip().capitalize() for e in selected)
    width = max((len(str(counts.get(s, 0))) for s in order), default=1)
    for sev in order:
        line = f"[{counts.get(sev, 0):>{width}}] {sev}"
        print(paint(line, sev_color[sev], stream), file=stream)

    print("--------------------------------", file=stream)

def write_outputs(rows: list[dict], release: str, out_dir: str, tag: str) -> list[str]:
    """Write the per-CVE CSV and the per-PTF order list. Returns file paths."""
    os.makedirs(out_dir, exist_ok=True)
    written = []

    rows = sorted(rows, key=lambda r: (SEV_ORDER.get(r["severity"].lower(), 9),
                                       cve_sort_key(r["cve"])))
    csv_path = os.path.join(out_dir, f"ibmi_{tag}_ptf_{release.replace('.', '')}.csv")
    fields = ["cve", "severity", "release", "lpp", "ptf", "download",
              "bulletin", "bulletin_url", "pub_date"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows({k: r.get(k, "") for k in fields} for r in rows)
    written.append(csv_path)

    # group by PTF for the "what do I actually order" list
    groups: dict[tuple[str, str, str], dict[str, str]] = collections.OrderedDict()
    na = []
    for r in rows:
        if not r["ptf"] or not PTF_RE.fullmatch(r["ptf"].split(",")[0].strip()):
            na.append(r)
            continue
        for ptf in [p.strip() for p in r["ptf"].split(",") if p.strip()]:
            key = (ptf, r["lpp"], r["download"])
            groups.setdefault(key, {})[r["cve"]] = r["severity"]

    def fmt(cve: str, sev: str) -> str:
        return f"{cve} ({sev})" if sev else cve

    list_path = os.path.join(out_dir, f"ibmi_{release.replace('.', '')}_ptf_order_list.txt")
    with open(list_path, "w", encoding="utf-8") as fh:
        fh.write(f"IBM i {release} PTFs - security bulletins {tag}\n")
        fh.write(f"{len(groups)} unique PTFs covering "
                 f"{len({c for v in groups.values() for c in v})} CVEs\n")
        fh.write("Columns: release <tab> LPP <tab> PTF <tab> download link "
                 "<tab> CVEs fixed (severity)\n")
        if na:
            na_sev = {r["cve"]: r["severity"] for r in na}
            fh.write(f"No {release} fix listed ({release} not affected): "
                     + ", ".join(fmt(c, na_sev[c])
                                 for c in sorted(na_sev, key=cve_sort_key)) + "\n")
        fh.write("\n")
        for (ptf, lpp, link), cvemap in sorted(groups.items()):
            fh.write(f"{release}\t{lpp}\t{ptf}\t{link}\t"
                     + ", ".join(fmt(c, cvemap[c])
                                 for c in sorted(cvemap, key=cve_sort_key)) + "\n")
    written.append(list_path)
    return written


# ------------------------------------------------------------------------ main


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Pull IBM i PTF numbers + download links from IBM security bulletins.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Note: IBM's discovery API only exposes the newest ~1000 records. "
               "Run daily so --cache-dir accumulates history.")
    ap.add_argument("--release", default=None,
                    help="restrict output to a single IBM i release, e.g. 7.5 "
                         "(default: all releases found)")
    ap.add_argument("--product", default="IBM i",
                    help="exact product name to filter on (default: 'IBM i'); "
                         "use '' for all products")
    ap.add_argument("--date", action="append", default=[],
                    help="publish date YYYY-MM-DD (repeatable)")
    ap.add_argument("--since", help="earliest publish date YYYY-MM-DD")
    ap.add_argument("--until", help="latest publish date YYYY-MM-DD")
    ap.add_argument("--cve-file",
                    help="restrict to CVE IDs found in this file (any format)")
    ap.add_argument("--nid", action="append", default=[],
                    help="bulletin node id; skips discovery (repeatable)")
    ap.add_argument("--out-dir", default=".", help="where to write outputs")
    ap.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR,
                    help="index + HTML cache location "
                         "(default: $IBM_PTF_CACHE_DIR or ~/.cache/ibm_ptf_pull)")
    ap.add_argument("--refresh", action="store_true",
                    help="re-download bulletin HTML instead of using the cache")
    ap.add_argument("--no-api", action="store_true",
                    help="use only the cached index (no network discovery call)")
    ap.add_argument("--jobs", type=int, default=4, help="parallel fetches (default 4)")
    ap.add_argument("--delay", type=float, default=0.4,
                    help="seconds to pause after each fetch (default 0.4)")
    ap.add_argument("--user-agent", default=DEFAULT_UA)
    ap.add_argument("--list-dates", action="store_true",
                    help="show publish dates held in the cache, then exit")
    ap.add_argument("--json", dest="json_out",
                    help="also dump parsed bulletins to this JSON path")
    args = ap.parse_args(argv)

    index = (load_index(args.cache_dir) if args.no_api
             else refresh_index(args.cache_dir, args.user_agent))

    if args.list_dates:
        counts = collections.Counter(
            v["pub_date"] for v in index.values()
            if not args.product
            or v["product"].strip().lower() == args.product.strip().lower())
        if not counts:
            print(f"cache holds nothing for product {args.product!r}")
            return 1
        print(f"publish dates in cache for product {args.product!r} "
              f"(CVE rows per date):")
        for date, n in sorted(counts.items()):
            print(f"  {date}  {n}")
        return 0

    # ---- work out which bulletins to parse
    if args.nid:
        nids = list(dict.fromkeys(args.nid))
        wanted = set(nids)
        selected = [e for e in select(index, None, None, None, None, None)
                    if e["nid"] in wanted]
        tag = "nids"
    else:
        cves = None
        if args.cve_file:
            with open(args.cve_file, encoding="utf-8", errors="replace") as fh:
                cves = set(CVE_RE.findall(fh.read()))
            if not cves:
                print(f"no CVE IDs found in {args.cve_file}", file=sys.stderr)
                return 1
        selected = select(index, args.product or None, set(args.date) or None,
                          args.since, args.until, cves)
        if not selected:
            print("nothing matched. Try --list-dates; the API window is only the "
                  "newest ~1000 records.", file=sys.stderr)
            return 1
        if cves:
            missing = cves - {e["cve"] for e in selected}
            if missing:
                print(f"[warn] {len(missing)} CVE(s) not in the index "
                      f"(outside API window?): "
                      f"{', '.join(sorted(missing, key=cve_sort_key)[:8])}"
                      + (" ..." if len(missing) > 8 else ""), file=sys.stderr)
        nids = sorted({e["nid"] for e in selected})
        dates = sorted({e["pub_date"] for e in selected if e["pub_date"]})
        tag = dates[0] if len(dates) == 1 else f"{dates[0]}_to_{dates[-1]}" if dates else "all"

    print(f"[fetch] {len(nids)} bulletin(s) -> parsing PTF tables", file=sys.stderr)

    def _fetch_one(n: str) -> dict | None:
        try:
            return get_bulletin(n, args.user_agent, args.cache_dir,
                                args.refresh, args.delay)
        except Exception as exc:  # noqa: BLE001 - skip this bulletin, keep the rest
            print(f"[warn] nid {n}: {exc}", file=sys.stderr)
            return None

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        bulletins = [b for b in pool.map(_fetch_one, nids) if b is not None]
    by_nid = {b["nid"]: b for b in bulletins}
    if not by_nid:
        print("no bulletins could be fetched/parsed", file=sys.stderr)
        return 2

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(bulletins, fh, indent=1)
        print(f"[json ] {args.json_out}", file=sys.stderr)

    # severity/CVE pairs come from the index; fall back to CVEs scraped from the
    # bulletin body for any nid index doesn't cover.
    by_nid_meta: dict[str, list[dict]] = collections.defaultdict(list)
    for entry in selected:
        if entry["cve"]:
            by_nid_meta[entry["nid"]].append(entry)
    pairs = []
    for nid in nids:
        if nid not in by_nid:
            continue  # bulletin failed to fetch/parse; already warned above
        entries = by_nid_meta.get(nid)
        if entries:
            pairs += [(nid, e["cve"], e["severity"], e["pub_date"]) for e in entries]
        else:
            pairs += [(nid, c, "", "") for c in by_nid[nid]["cves"]]

    releases = ([args.release] if args.release
                else sorted({f["release"] for b in bulletins for f in b["fixes"]}))
    if not releases:
        print(f"no IBM i release/PTF rows found in {len(bulletins)} bulletin(s) "
              f"for product {args.product!r} - it may not be an IBM i product, "
              "or the bulletin layout changed.", file=sys.stderr)
        print_severity_summary(selected)
        return 0

    for release in releases:
        rows = []
        for nid, cve, sev, pub in pairs:
            b = by_nid[nid]
            hits = [f for f in b["fixes"] if f["release"] == release]
            if hits:
                rows.append({
                    "cve": cve, "severity": sev, "release": release,
                    "lpp": ", ".join(dict.fromkeys(h["lpp"] for h in hits if h["lpp"])),
                    "ptf": ", ".join(dict.fromkeys(
                        p for h in hits for p in h["ptfs"])),
                    "download": next((h["link"] for h in hits if h["link"]), ""),
                    "bulletin": b["title"], "bulletin_url": b["url"], "pub_date": pub,
                })
            else:
                why = (f"N/A ({release} not affected)"
                       if b["affected_releases"] and release not in b["affected_releases"]
                       else "N/A (no PTF row found)")
                rows.append({
                    "cve": cve, "severity": sev, "release": release, "lpp": "",
                    "ptf": why, "download": "", "bulletin": b["title"],
                    "bulletin_url": b["url"], "pub_date": pub,
                })
        paths = write_outputs(rows, release, args.out_dir, tag)
        fixed = sum(1 for r in rows if not r["ptf"].startswith("N/A"))
        print(paint(f"[{release}] {len(rows)} CVEs: {fixed} with a PTF, "
                    f"{len(rows) - fixed} without "
                    f"-> {', '.join(os.path.basename(p) for p in paths)}",
                    "green", sys.stderr), file=sys.stderr)

    print_severity_summary(selected)
    return 0


if __name__ == "__main__":
    sys.exit(main())
