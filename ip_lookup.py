"""
ip_lookup.py
Analyses a list of IP addresses and produces a CSV with:
  - geolocation (country, region, city, coordinates)
  - ISP / organization / ASN
  - proxy-VPN-hosting flags
  - reputation (optional, needs a free AbuseIPDB key)

Usage:
    python ip_lookup.py ip_list.txt
    python ip_lookup.py ip_list.txt -o report.csv
    python ip_lookup.py ip_list.txt --abuse-key YOUR_KEY

Arguments:
    input: text file with one IP per line (or several IPs separated by commas/spaces/semicolons)
    -o, --output: destination CSV file (default: report_ip.csv)
    --abuse-key: AbuseIPDB key (alternatively: ABUSEIPDB_KEY environment variable)
    --no-cache: fetch everything again, ignoring what is already stored
                (the cache is refreshed, never deleted)

CSV columns:
    picked in the COLUMNS dictionary below, by putting True or False next to
    the name. Moving the lines around also changes their order in the report.
    'message' is off by default: it only fills in when a lookup fails, and
    the summary counts those failures anyway.

Dependencies:
    pip install requests
"""

import argparse
import csv
import ipaddress
import json
import os
import sqlite3
import sys
import time
from collections import Counter

import requests


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

# ip-api.com: free, no sign-up, "batch" endpoint takes 100 IPs at a time.
# The free plan allows about 15 batch calls per minute -> ~1500 IPs/minute.
# The exact pace is taken from the X-Rl / X-Ttl response headers; BATCH_PAUSE
# is only the fallback for when those headers are missing.
IPAPI_URL = "http://ip-api.com/batch"
IPAPI_FIELDS = "status,message,query,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,asname,proxy,hosting,mobile"
BATCH_SIZE = 100
BATCH_PAUSE = 4.5  # seconds to wait between one batch and the next
POLITE_PAUSE = 0.5  # between batches, while the rate-limit window has room

# AbuseIPDB: free but you must register on abuseipdb.com to get a key.
# Free plan: 1000 checks a day, one IP per call.
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSE_PAUSE = 0.6

# The cache avoids requesting the same IP twice: it saves time and, above
# all, it does not burn through the free quotas.
CACHE_DB = "cache_ip.sqlite"
CACHE_TTL = 7 * 24 * 3600  # one week, in seconds

# Columns of the final CSV, in the order they appear.
# Set False to keep a column out of the report. The data is downloaded and
# cached anyway: if you switch it back to True tomorrow, the CSV is rebuilt
# in seconds without spending any quota.
# To change the column order, just move the lines below.
COLUMNS = {
    "ip":            True,
    "status":        True,
    "message":       False,  # why a lookup failed; empty when it succeeded
    "country":       True,
    "country_code":  True,
    "region":        True,
    "city":          True,
    "postal_code":   False,
    "lon":           False,
    "lat":           False,
    "isp":           True,
    "organization":  False,
    "asn":           False,
    "asn_name":      True,
    "proxy_vpn":     True,
    "hosting":       True,
    "mobile":        False,
    "abuse_score":   True,
    "reports":       True,
    "abuse_domain":  True,
}


def active_columns():
    """The names set to True, in the order they appear in COLUMNS."""
    return [name for name, enabled in COLUMNS.items() if enabled]


# ---------------------------------------------------------------------------
# CACHE
# ---------------------------------------------------------------------------

class Cache:
    """Small file-backed store, so the same request is not repeated.

    Writes are queued and committed in groups by flush(). One commit per
    entry means one fsync per entry, which on ~15k IPs costs about 25
    seconds against 0.1 for a single transaction.
    """

    def __init__(self, path=CACHE_DB, ignore_existing=False):
        # ignore_existing: every lookup misses, but new answers are still
        # stored. This is what --no-cache does, so that refreshing the
        # geolocation does not throw away the AbuseIPDB results, which
        # cost daily quota.
        self.ignore_existing = ignore_existing
        self.pending = []
        self.conn = sqlite3.connect(path)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS entries (
                   key        TEXT PRIMARY KEY,
                   payload    TEXT NOT NULL,
                   fetched_at REAL NOT NULL
               )"""
        )
        self.conn.commit()

    def get(self, key):
        if self.ignore_existing:
            return None
        row = self.conn.execute(
            "SELECT payload, fetched_at FROM entries WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        payload, fetched_at = row
        if time.time() - fetched_at > CACHE_TTL:
            return None  # too old, better to ask again
        return json.loads(payload)

    def put(self, key, value):
        """Queue an entry. Nothing reaches the disk until flush()."""
        self.pending.append((key, json.dumps(value), time.time()))

    def flush(self):
        """Commit the queued entries in a single transaction."""
        if not self.pending:
            return
        self.conn.executemany(
            "INSERT OR REPLACE INTO entries (key, payload, fetched_at) VALUES (?, ?, ?)",
            self.pending,
        )
        self.conn.commit()
        self.pending.clear()

    def purge_expired(self):
        """Delete entries past CACHE_TTL and return how many went.

        get() already ignores them, so without this they would sit in the
        file for ever, growing it with rows nothing will ever read again.
        """
        cutoff = time.time() - CACHE_TTL
        removed = self.conn.execute(
            "DELETE FROM entries WHERE fetched_at < ?", (cutoff,)
        ).rowcount
        self.conn.commit()
        return removed

    def close(self):
        self.flush()
        self.conn.close()


# ---------------------------------------------------------------------------
# READING THE INPUT
# ---------------------------------------------------------------------------

def read_ips(path):
    """Read the input file and return (valid_ips, skipped).

    Accepts one IP per line, or several IPs separated by commas, spaces
    or semicolons (e.g. "79.6.172.189, 23.206.214.188, 10.67.112.28").
    Empty lines and lines starting with # are ignored.

    'skipped' is {address: [reason, occurrences]}, one entry per distinct
    rejected address. Deduplication happens before the private-range test
    on purpose: an input file where the same internal IP repeats hundreds
    of thousands of times must not build a list just as long.
    """
    valid = []
    skipped = {}
    already_seen = set()

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # split the line on commas, spaces or semicolons
            pieces = line.replace(",", " ").replace(";", " ").split()

            for piece in pieces:
                candidate = piece.strip('"').strip("'")

                try:
                    address = ipaddress.ip_address(candidate)
                except ValueError:
                    continue  # not a valid IP, silently ignored

                # normalised form, so the many ways of writing the same
                # IPv6 address collapse into one cache key
                key = str(address)

                if key in skipped:
                    skipped[key][1] += 1
                    continue

                if key in already_seen:
                    continue  # duplicate

                if address.is_private or address.is_loopback or address.is_reserved or address.is_link_local or address.is_multicast:
                    skipped[key] = ["private/local/reserved/link-local/multicast IP", 1]
                    continue

                already_seen.add(key)
                valid.append(key)

    return valid, skipped


def in_chunks(items, size):
    """Split a list into pieces of 'size' elements."""
    for i in range(0, len(items), size):
        yield items[i:i + size]


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def new_session():
    """One connection pool reused by every call.

    requests.get/post open a fresh connection each time. Over a full run
    that is one handshake per batch for ip-api and, worse, one TLS
    handshake per IP for AbuseIPDB: on 1000 IPs it adds up to minutes
    spent doing nothing but shaking hands.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": "ip_lookup"})
    return session


def wait_for_rate_limit(response, fallback=BATCH_PAUSE):
    """Pause between batches following ip-api's own headers.

    ip-api reports X-Rl (calls left in the current window) and X-Ttl
    (seconds until it resets). Reading them beats guessing a fixed delay:
    when the window still has room a short pause is enough, and when it
    runs out, waiting exactly X-Ttl is what avoids the 429 instead of
    recovering from it. Falls back to the fixed pause if the headers are
    missing or unreadable, which is what a proxy in the middle may cause.
    """
    try:
        left = int(response.headers.get("X-Rl", -1))
        ttl = int(response.headers.get("X-Ttl", -1))
    except (TypeError, ValueError):
        left = ttl = -1

    if left < 0 or ttl < 0:
        time.sleep(fallback)
    elif left == 0:
        print(f"  rate-limit window used up, waiting {ttl + 1}s...")
        time.sleep(ttl + 1)
    else:
        time.sleep(POLITE_PAUSE)


# ---------------------------------------------------------------------------
# GEOLOCATION AND ISP (ip-api.com)
# ---------------------------------------------------------------------------

def geolocate(ips, cache, session):
    """Return a dictionary {ip: geo_data} for every IP passed in."""
    results = {}
    to_fetch = []

    for ip in ips:
        cached = cache.get("geo:" + ip)
        if cached is not None:
            results[ip] = cached
        else:
            to_fetch.append(ip)

    if not to_fetch:
        print("Geolocation: everything already cached.")
        return results

    chunks = list(in_chunks(to_fetch, BATCH_SIZE))
    print(f"Geolocation: {len(to_fetch)} IPs to query "
          f"in {len(chunks)} batches.")

    max_retries = 3
    for number, chunk in enumerate(chunks, start=1):
        body = [{"query": ip, "fields": IPAPI_FIELDS} for ip in chunk]

        response = None
        for attempt in range(max_retries):
            try:
                response = session.post(IPAPI_URL, json=body, timeout=30)
                break
            except requests.RequestException as error:
                if attempt < max_retries - 1:
                    wait = 5 * (attempt + 1)
                    print(f"  batch {number}: network error ({error}), "
                          f"retrying in {wait}s...")
                    time.sleep(wait)
                else:
                    print(f"  batch {number}: network error ({error}), skipping it")

        if response is None:
            continue

        if response.status_code == 429:
            print("  rate limit reached, waiting 60 seconds...")
            time.sleep(60)
            try:
                response = session.post(IPAPI_URL, json=body, timeout=30)
            except requests.RequestException as error:
                print(f"  batch {number}: network error ({error}), skipping it")
                continue

        if response.status_code != 200:
            print(f"  batch {number}: HTTP {response.status_code} response, skipping it")
            continue

        # a 200 does not guarantee JSON: a captive portal or a company
        # proxy answers with an HTML page and would crash the whole run
        try:
            payload = response.json()
        except ValueError:
            print(f"  batch {number}: response is not valid JSON, skipping it")
            continue

        if not isinstance(payload, list):
            print(f"  batch {number}: unexpected response {payload!r}, skipping it")
            continue

        for item in payload:
            ip = item.get("query")
            if not ip:
                continue
            results[ip] = item
            # only successful answers are cached: a temporary "fail" would
            # otherwise stay frozen for a whole week
            if item.get("status") == "success":
                cache.put("geo:" + ip, item)

        cache.flush()
        print(f"  batch {number}/{len(chunks)} done")

        if number < len(chunks):
            wait_for_rate_limit(response)

    return results


# ---------------------------------------------------------------------------
# REPUTATION (AbuseIPDB)
# ---------------------------------------------------------------------------

def reputation(ips, api_key, cache, session, daily_limit=1000):
    """Return {ip: reputation_data}. Returns empty if the key is missing."""
    if not api_key:
        print("Reputation: no AbuseIPDB key, skipping.")
        return {}

    results = {}
    to_fetch = []

    for ip in ips:
        cached = cache.get("abuse:" + ip)
        if cached is not None:
            results[ip] = cached
        else:
            to_fetch.append(ip)

    if len(to_fetch) > daily_limit:
        print(f"Warning: {len(to_fetch)} IPs to check but the daily quota "
              f"is {daily_limit}. Checking only the first ones.")
        to_fetch = to_fetch[:daily_limit]

    print(f"Reputation: {len(to_fetch)} IPs to query.")
    headers = {"Key": api_key, "Accept": "application/json"}

    for number, ip in enumerate(to_fetch, start=1):
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        try:
            response = session.get(
                ABUSE_URL, headers=headers, params=params, timeout=20
            )
        except requests.RequestException as error:
            print(f"  {ip}: network error ({error}), skipping it")
            continue

        if response.status_code == 429:
            print("  AbuseIPDB quota exhausted, stopping here.")
            break

        if response.status_code != 200:
            print(f"  {ip}: HTTP {response.status_code} response, skipping it")
            continue

        try:
            data = response.json().get("data", {})
        except ValueError:
            print(f"  {ip}: response is not valid JSON, skipping it")
            continue

        results[ip] = data
        cache.put("abuse:" + ip, data)
        # committed straight away: each of these answers costs a slot of
        # the daily quota, and the 0.6s pause below dwarfs the fsync
        cache.flush()

        if number % 50 == 0:
            print(f"  {number}/{len(to_fetch)}")

        time.sleep(ABUSE_PAUSE)

    return results


# ---------------------------------------------------------------------------
# BUILDING THE ROWS AND WRITING THE CSV
# ---------------------------------------------------------------------------

def build_row(ip, geo, abuse):
    """Merge the data from the two sources into a single CSV row."""
    geo = geo or {}
    abuse = abuse or {}

    return {
        "ip": ip,
        "status": geo.get("status", "unknown"),
        "message": geo.get("message", ""),
        "country": geo.get("country", ""),
        "country_code": geo.get("countryCode", ""),
        "region": geo.get("regionName", ""),
        "city": geo.get("city", ""),
        "postal_code": geo.get("zip", ""),
        "lat": geo.get("lat", ""),
        "lon": geo.get("lon", ""),
        "isp": geo.get("isp", ""),
        "organization": geo.get("org", ""),
        "asn": geo.get("as", ""),
        "asn_name": geo.get("asname", ""),
        "proxy_vpn": "yes" if geo.get("proxy") else "no",
        "hosting": "yes" if geo.get("hosting") else "no",
        "mobile": "yes" if geo.get("mobile") else "no",
        "abuse_score": abuse.get("abuseConfidenceScore", ""),
        "reports": abuse.get("totalReports", ""),
        "abuse_domain": abuse.get("domain", ""),
    }


def check_columns():
    """Check COLUMNS at startup, before wasting half an hour of calls.

    A wrong name in there would not show up until write_csv, that is,
    after every API has already been queried.
    """
    available = list(build_row("0.0.0.0", None, None))

    unknown = [name for name in COLUMNS if name not in available]
    if unknown:
        print("Error in COLUMNS, these names do not exist: "
              + ", ".join(unknown))
        print("Valid names: " + ", ".join(available))
        sys.exit(1)

    if not active_columns():
        print("Error: every entry in COLUMNS is False, the CSV would be empty.")
        sys.exit(1)


def write_csv(rows, path):
    columns = active_columns()

    def write(where):
        # utf-8-sig makes Excel open the file correctly
        with open(where, "w", newline="", encoding="utf-8-sig") as f:
            # extrasaction="ignore": build_row always prepares every field,
            # here we keep only the active ones
            writer = csv.DictWriter(f, fieldnames=columns, delimiter=";",
                                    extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

    try:
        write(path)
    except PermissionError:
        # if the file is open in another program (e.g. Excel),
        # try an alternative name
        base, ext = os.path.splitext(path)
        alt_path = f"{base}_2{ext}"
        print(f"  cannot write {path} (file in use?), "
              f"trying {alt_path}")
        write(alt_path)
        return alt_path
    return path


def print_summary(rows):
    """A couple of quick counts to see what came out."""
    if not rows:
        return

    countries = Counter(row["country"] or "?" for row in rows)
    isps = Counter(row["isp"] or "?" for row in rows)
    suspicious = sum(1 for row in rows
                     if row["proxy_vpn"] == "yes" or row["hosting"] == "yes")

    # the reason a lookup failed is in a column that is off by default,
    # so without this the failures would pass unnoticed
    failures = Counter(row["message"] or row["status"]
                       for row in rows if row["status"] != "success")

    print("\n--- SUMMARY ---")
    print(f"IPs analysed: {len(rows)}")
    print(f"Proxy/VPN or hosting: {suspicious}")

    if failures:
        print(f"Failed lookups: {sum(failures.values())}")
        for reason, count in failures.most_common():
            print(f"  {reason}: {count}")

    print("\nTop 5 countries:")
    for name, count in countries.most_common(5):
        print(f"  {name}: {count}")

    print("\nTop 5 ISPs:")
    for name, count in isps.most_common(5):
        print(f"  {name}: {count}")


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyse a list of IPs: geolocation, ISP, reputation."
    )
    parser.add_argument("input", help="text file with one IP per line")
    parser.add_argument("-o", "--output", default="report_ip.csv",
                        help="destination CSV file (default: report_ip.csv)")
    parser.add_argument("--abuse-key", default=os.environ.get("ABUSEIPDB_KEY"),
                        help="AbuseIPDB key (alternatively: ABUSEIPDB_KEY "
                             "environment variable)")
    parser.add_argument("--no-cache", action="store_true",
                        help="fetch everything again, ignoring what is already "
                             "stored; the cache is updated with the fresh "
                             "answers, nothing is deleted")
    args = parser.parse_args()

    # a Windows console is usually cp1252: an ISP name in Cyrillic or Greek
    # would raise UnicodeEncodeError on the very last print, after the CSV
    # has already been written. Replacing the odd character beats losing
    # the summary.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    check_columns()

    if not os.path.exists(args.input):
        print(f"File not found: {args.input}")
        sys.exit(1)

    ips, skipped = read_ips(args.input)
    print(f"Read {len(ips)} valid, distinct IPs.")
    if skipped:
        occurrences = sum(count for _, count in skipped.values())
        print(f"Skipped {len(skipped)} distinct values "
              f"({occurrences} occurrences). First 5:")
        for value, (reason, count) in list(skipped.items())[:5]:
            print(f"  {value} (x{count}) -> {reason}")

    if not ips:
        print("Nothing to analyse.")
        sys.exit(0)

    cache = Cache(ignore_existing=args.no_cache)
    session = new_session()
    try:
        expired = cache.purge_expired()
        if expired:
            print(f"Cache: removed {expired} expired entries.")

        geo_data = geolocate(ips, cache, session)
        abuse_data = reputation(ips, args.abuse_key, cache, session)
    finally:
        cache.close()
        session.close()

    rows = [
        build_row(ip, geo_data.get(ip), abuse_data.get(ip))
        for ip in ips
    ]

    final_path = write_csv(rows, args.output)
    print(f"\nWritten: {final_path}")
    print_summary(rows)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # the cache is flushed by the finally in main(), so a long run can
        # be stopped and picked up again later without losing the work
        print("\nInterrupted. Everything fetched so far is in the cache.")
        sys.exit(130)
