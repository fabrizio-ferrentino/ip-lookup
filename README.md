# ip-lookup

Takes a list of IP addresses and produces a CSV with geolocation, ISP/ASN,
proxy-VPN-hosting flags and, optionally, AbuseIPDB reputation.

## Setup

```
python -m venv venv
venv\Scripts\Activate.ps1        # Windows PowerShell
source venv/bin/activate         # Linux / macOS
pip install -r requirements.txt
```

## Usage

```
python ip_lookup.py ip/ip.txt
python ip_lookup.py ip/ip.txt -o report.csv
python ip_lookup.py ip/ip.txt --abuse-key YOUR_KEY
```

The input file takes one IP per line, or several separated by commas, spaces
or semicolons. Blank lines and lines starting with `#` are ignored, and so
are private, loopback, reserved, link-local and multicast addresses.

## Options

| Option | Meaning |
| --- | --- |
| `-o`, `--output` | Destination CSV (default: `report_ip.csv`) |
| `--abuse-key` | AbuseIPDB key, or set `ABUSEIPDB_KEY` in the environment |
| `--no-cache` | Fetch everything again; the cache is refreshed, never deleted |

## CSV columns

Pick them in the `COLUMNS` dictionary at the top of `ip_lookup.py` by setting
each name to `True` or `False`. Moving the lines changes the column order.
Disabled columns are still fetched and cached, so switching one back on
rebuilds the report in seconds without spending API quota.

## Notes

- **ip-api.com** needs no registration but is HTTP-only on the free plan and
  is restricted to non-commercial use. Pacing follows the rate-limit headers
  the API itself returns.
- **AbuseIPDB** is optional and needs a free key from abuseipdb.com. The free
  plan allows 1000 checks a day; beyond that the script stops and picks up
  where it left off on the next run.
- Answers are cached in `cache_ip.sqlite` for a week, so re-runs are cheap.
  Interrupting a long run with Ctrl+C keeps everything fetched so far.

## License

MIT — see [LICENSE](LICENSE).
