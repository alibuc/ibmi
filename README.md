# ibmi_ptf_pull

Pull IBM i security-bulletin PTF numbers and download links from IBM's
security bulletins, and produce a per-CVE CSV plus a "what to order" PTF list.

## How it works

Discovery uses IBM's bulletin JSON API; bulletin bodies are parsed from the
server-rendered HTML. 

The API only exposes the newest ~1000 records, 
so every run merges the snapshot into a local cache:

(`--cache-dir`, default `~/.cache/ibm_ptf_pull` or `$IBM_PTF_CACHE_DIR`).

Run daily (cron) and the cache accumulates history beyond the API window.

## Usage

```sh
# everything IBM i published on one day, all releases
./ibmi_ptf_pull.py --date 2026-08-11

# restrict to a single release
./ibmi_ptf_pull.py --date 2026-08-11 --release 7.5

# restrict to specific CVEs (any file with CVE-looking tokens)
./ibmi_ptf_pull.py --cve-file list_of_cve

# specific bulletins by node id, skipping discovery
./ibmi_ptf_pull.py --nid 7283359 --nid 7283281

# what publish dates does the cache hold?
./ibmi_ptf_pull.py --list-dates
```

Run `./ibmi_ptf_pull.py --help` for all options.

## Output

- `ibmi_<dates>_ptf_<release>.csv` — one row per CVE (severity, release, LPP,
  PTF, download link, bulletin).
- `ibmi_<release>_ptf_order_list.txt` — unique PTFs to order, with the CVEs
  (and severity) each one fixes.
- A severity summary is printed to the terminal (colorized when supported).

## Requirements

Python 3.10+ (standard library only).
