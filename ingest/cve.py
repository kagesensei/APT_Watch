import json
import pathlib
import sys

import duckdb
import requests

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
RAW.mkdir(parents=True, exist_ok=True)
DB = ROOT / "data" / "cti.duckdb"

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
raw = RAW / "known_exploited_vulnerabilities.json"
raw.write_bytes(requests.get(URL, timeout=60).content)

data = json.loads(raw.read_text(encoding="utf-8"))

kev_rows = []
cwe_rows = []
for v in data["vulnerabilities"]:
    kev_rows.append(
        (
            v["cveID"],
            v.get("vendorProject"),
            v.get("product"),
            v.get("vulnerabilityName"),
            v.get("dateAdded"),
            v.get("dueDate"),
            v.get("shortDescription"),
            v.get("requiredAction"),
            v.get("knownRansomwareCampaignUse"),
        )
    )
    for cwe_id in v.get("cwes") or []:
        cwe_rows.append((v["cveID"], cwe_id))

con = duckdb.connect(str(DB))
con.execute(
    "CREATE OR REPLACE TABLE kev("
    "cve_id VARCHAR, vendor_project VARCHAR, product VARCHAR, vulnerability_name VARCHAR, "
    "date_added VARCHAR, due_date VARCHAR, short_description VARCHAR, required_action VARCHAR, "
    "known_ransomware VARCHAR)"
)
con.executemany("INSERT INTO kev VALUES (?,?,?,?,?,?,?,?,?)", kev_rows)

con.execute("CREATE OR REPLACE TABLE kev_cwe(cve_id VARCHAR, cwe_id VARCHAR)")
con.executemany("INSERT INTO kev_cwe VALUES (?,?)", cwe_rows)

for table in ("kev", "kev_cwe"):
    print(table, con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

# --- data quality: compare against the catalog's own published count ---
published_count = data["count"]
actual_count = con.execute("SELECT COUNT(DISTINCT cve_id) FROM kev").fetchone()[0]
status = "PASS" if actual_count == published_count else "FAIL"
print(f"DQ [{status}] kev: {actual_count} distinct vs {published_count} published by CISA catalog {data['catalogVersion']}")

if status == "FAIL":
    print("DATA QUALITY CHECK FAILED: kev", file=sys.stderr)
    sys.exit(1)
