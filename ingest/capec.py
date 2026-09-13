import pathlib
import re
import sys

import duckdb
import requests
from stix2 import Filter, MemoryStore

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
RAW.mkdir(parents=True, exist_ok=True)
DB = ROOT / "data" / "cti.duckdb"

URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
raw = RAW / "capec.json"
raw.write_bytes(requests.get(URL, timeout=60).content)

store = MemoryStore()
store.load_from_file(str(raw))

INACTIVE_STATUSES = {"Deprecated", "Obsolete"}
TAG_RE = re.compile(r"<[^>]+>")


def clean_description(text):
    if not text:
        return None
    return re.sub(r"\s+", " ", TAG_RE.sub(" ", text)).strip()


def external_ids(ap, source_name):
    return [
        ref["external_id"]
        for ref in getattr(ap, "external_references", [])
        if ref.get("source_name") == source_name and ref.get("external_id")
    ]


patterns = store.query([Filter("type", "=", "attack-pattern")])
active_patterns = [ap for ap in patterns if getattr(ap, "x_capec_status", None) not in INACTIVE_STATUSES]

capec_rows = []
cwe_rows = []
technique_rows = []
for ap in active_patterns:
    capec_ids = external_ids(ap, "capec")
    if not capec_ids:
        continue
    capec_id = capec_ids[0]
    capec_rows.append((capec_id, ap.name, clean_description(getattr(ap, "description", None))))
    for cwe_id in external_ids(ap, "cwe"):
        cwe_rows.append((capec_id, cwe_id))
    for technique_id in external_ids(ap, "ATTACK"):
        technique_rows.append((capec_id, technique_id))

con = duckdb.connect(str(DB))
con.execute("CREATE OR REPLACE TABLE capec(capec_id VARCHAR, name VARCHAR, description VARCHAR)")
con.executemany("INSERT INTO capec VALUES (?,?,?)", capec_rows)

con.execute("CREATE OR REPLACE TABLE capec_cwe(capec_id VARCHAR, cwe_id VARCHAR)")
con.executemany("INSERT INTO capec_cwe VALUES (?,?)", cwe_rows)

con.execute("CREATE OR REPLACE TABLE capec_technique(capec_id VARCHAR, technique_id VARCHAR)")
con.executemany("INSERT INTO capec_technique VALUES (?,?)", technique_rows)

for table in ("capec", "capec_cwe", "capec_technique"):
    print(table, con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

# --- data quality: recount active attack-patterns independently of the extraction loop above ---
published_active = sum(
    1
    for ap in store.query([Filter("type", "=", "attack-pattern")])
    if getattr(ap, "x_capec_status", None) not in INACTIVE_STATUSES
)
actual_capec = con.execute("SELECT COUNT(DISTINCT capec_id) FROM capec").fetchone()[0]
status = "PASS" if actual_capec == published_active else "FAIL"
print(f"DQ [{status}] capec: {actual_capec} distinct vs {published_active} active attack-patterns in source")

if status == "FAIL":
    print("DATA QUALITY CHECK FAILED: capec", file=sys.stderr)
    sys.exit(1)
