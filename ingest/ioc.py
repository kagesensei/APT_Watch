import csv
import io
import json
import pathlib
import sys

import duckdb
import requests

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
RAW.mkdir(parents=True, exist_ok=True)
DB = ROOT / "data" / "cti.duckdb"

URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
MALWAREBAZAAR_URL = "https://bazaar.abuse.ch/export/csv/recent/"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def fetch(url, filename):
    raw = RAW / filename
    raw.write_bytes(requests.get(url, timeout=60).content)
    return raw


def parse_csv_rows(path):
    """abuse.ch CSVs are '#'-commented; the last comment line is the header."""
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    data_lines = [l for l in lines if l and not l.startswith("#")]
    header_line = next(l for l in reversed(lines) if l.startswith("# ") and "," in l)
    header = [h.strip().strip('"') for h in header_line.lstrip("#").strip().split(",")]
    reader = csv.reader(data_lines, skipinitialspace=True)
    return header, list(reader)


con = duckdb.connect(str(DB))
failures = []

# --- URLhaus (malicious URLs) ---
urlhaus_raw = fetch(URLHAUS_URL, "urlhaus.csv")
header, rows = parse_csv_rows(urlhaus_raw)
idx = {name: i for i, name in enumerate(header)}
url_rows = [
    (
        r[idx["id"]], r[idx["url"]], r[idx["dateadded"]], r[idx["threat"]],
        r[idx["tags"]], r[idx["url_status"]], r[idx["urlhaus_link"]],
    )
    for r in rows
]
con.execute(
    "CREATE OR REPLACE TABLE ioc_url(id VARCHAR, url VARCHAR, date_added VARCHAR, "
    "threat VARCHAR, tags VARCHAR, status VARCHAR, urlhaus_link VARCHAR)"
)
con.executemany("INSERT INTO ioc_url VALUES (?,?,?,?,?,?,?)", url_rows)
actual = con.execute("SELECT COUNT(*) FROM ioc_url").fetchone()[0]
status = "PASS" if actual == len(rows) else "FAIL"
if status == "FAIL":
    failures.append("ioc_url")
print(f"ioc_url {actual}")
print(f"DQ [{status}] ioc_url: {actual} loaded vs {len(rows)} rows in source CSV")

# --- MalwareBazaar (file hashes) ---
mb_raw = fetch(MALWAREBAZAAR_URL, "malwarebazaar.csv")
header, rows = parse_csv_rows(mb_raw)
idx = {name: i for i, name in enumerate(header)}
hash_rows = [
    (
        r[idx["sha256_hash"]], r[idx["md5_hash"]], r[idx["sha1_hash"]],
        r[idx["file_name"]], r[idx["signature"]], r[idx["first_seen_utc"]],
    )
    for r in rows
]
con.execute(
    "CREATE OR REPLACE TABLE ioc_hash(sha256 VARCHAR, md5 VARCHAR, sha1 VARCHAR, "
    "file_name VARCHAR, signature VARCHAR, first_seen VARCHAR)"
)
con.executemany("INSERT INTO ioc_hash VALUES (?,?,?,?,?,?)", hash_rows)
actual = con.execute("SELECT COUNT(*) FROM ioc_hash").fetchone()[0]
status = "PASS" if actual == len(rows) else "FAIL"
if status == "FAIL":
    failures.append("ioc_hash")
print(f"ioc_hash {actual}")
print(f"DQ [{status}] ioc_hash: {actual} loaded vs {len(rows)} rows in source CSV")

# --- Feodo Tracker (botnet C2 IPs) ---
feodo_raw = fetch(FEODO_URL, "feodotracker.json")
feodo_data = json.loads(feodo_raw.read_text(encoding="utf-8"))
c2_rows = [
    (
        e["ip_address"], e.get("port"), e.get("malware"),
        e.get("first_seen"), e.get("last_online"), e.get("status"),
    )
    for e in feodo_data
]
con.execute(
    "CREATE OR REPLACE TABLE ioc_c2(ip_address VARCHAR, port INTEGER, malware VARCHAR, "
    "first_seen VARCHAR, last_online VARCHAR, status VARCHAR)"
)
con.executemany("INSERT INTO ioc_c2 VALUES (?,?,?,?,?,?)", c2_rows)
actual = con.execute("SELECT COUNT(*) FROM ioc_c2").fetchone()[0]
status = "PASS" if actual == len(feodo_data) else "FAIL"
if status == "FAIL":
    failures.append("ioc_c2")
print(f"ioc_c2 {actual}")
print(f"DQ [{status}] ioc_c2: {actual} loaded vs {len(feodo_data)} entries in source JSON")

# --- Crosswalk: malware family name -> known ATT&CK software (exact, case-insensitive) ---
con.execute(
    "CREATE OR REPLACE TABLE ioc_software(source_table VARCHAR, malware_name VARCHAR, "
    "software_id VARCHAR, software_name VARCHAR)"
)
crosswalk_rows = []
for source_table, name_col in (("ioc_hash", "signature"), ("ioc_c2", "malware")):
    matches = con.execute(
        f"SELECT DISTINCT i.{name_col}, s.software_id, s.software_name "
        f"FROM {source_table} i "
        f"JOIN (SELECT DISTINCT software_id, software_name FROM actor_software) s "
        f"ON lower(i.{name_col}) = lower(s.software_name) "
        f"WHERE i.{name_col} IS NOT NULL AND i.{name_col} != ''"
    ).fetchall()
    for malware_name, software_id, software_name in matches:
        crosswalk_rows.append((source_table, malware_name, software_id, software_name))
con.executemany("INSERT INTO ioc_software VALUES (?,?,?,?)", crosswalk_rows)
print(f"ioc_software {len(crosswalk_rows)}")

if failures:
    print(f"DATA QUALITY CHECK FAILED: {', '.join(failures)}", file=sys.stderr)
    sys.exit(1)
