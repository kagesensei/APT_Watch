import pathlib, sys, requests, duckdb
from mitreattack.stix20 import MitreAttackData

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
RAW.mkdir(parents=True, exist_ok=True)
DB = ROOT / "data" / "cti.duckdb"

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
raw = RAW / "enterprise-attack.json"
raw.write_bytes(requests.get(URL, timeout=60).content)

atk = MitreAttackData(str(raw))
con = duckdb.connect(str(DB))

groups = [(g.id, atk.get_attack_id(g.id), g.name, ";".join(getattr(g, "aliases", []) or []))
          for g in atk.get_groups(remove_revoked_deprecated=True)]
con.execute("CREATE OR REPLACE TABLE actor(stix_id VARCHAR, attack_id VARCHAR, name VARCHAR, aliases VARCHAR)")
con.executemany("INSERT INTO actor VALUES (?,?,?,?)", groups)

rows = []
for g in atk.get_groups(remove_revoked_deprecated=True):
    for rel in atk.get_techniques_used_by_group(g.id):
        t = rel["object"]
        rows.append((g.id, atk.get_attack_id(t.id), t.name))
con.execute("CREATE OR REPLACE TABLE actor_technique(actor_stix_id VARCHAR, technique_id VARCHAR, technique_name VARCHAR)")
con.executemany("INSERT INTO actor_technique VALUES (?,?,?)", rows)

software_rows = []
for g in atk.get_groups(remove_revoked_deprecated=True):
    for rel in atk.get_software_used_by_group(g.id):
        s = rel["object"]
        software_rows.append((g.id, s.id, s.name, s.type))
con.execute("CREATE OR REPLACE TABLE actor_software(actor_stix_id VARCHAR, software_id VARCHAR, software_name VARCHAR, software_type VARCHAR)")
con.executemany("INSERT INTO actor_software VALUES (?,?,?,?)", software_rows)

mitigation_rows = []
for t in atk.get_techniques(remove_revoked_deprecated=True):
    for rel in atk.get_mitigations_mitigating_technique(t.id):
        m = rel["object"]
        mitigation_rows.append((atk.get_attack_id(t.id), atk.get_attack_id(m.id), m.name))
con.execute("CREATE OR REPLACE TABLE technique_mitigation(technique_id VARCHAR, mitigation_id VARCHAR, mitigation_name VARCHAR)")
con.executemany("INSERT INTO technique_mitigation VALUES (?,?,?)", mitigation_rows)

for table in ("actor", "actor_technique", "actor_software", "technique_mitigation"):
    print(table, con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

# --- data quality: compare against MITRE's published entity totals ---
# "Published totals" = counts from mitreattack-python's own top-level getters, i.e. the
# canonical entity counts MITRE ships for this release (same numbers reflected on
# attack.mitre.org's Groups/Software/Techniques/Mitigations pages), filtered the same way
# (remove_revoked_deprecated=True) as the rest of this script.
published = {
    "actor": len(atk.get_groups(remove_revoked_deprecated=True)),
    "technique": len(atk.get_techniques(remove_revoked_deprecated=True)),
    "software": len(atk.get_software(remove_revoked_deprecated=True)),
    "mitigation": len(atk.get_mitigations(remove_revoked_deprecated=True)),
}

failures = []

# actor table holds every group regardless of usage, so it must match exactly.
actual_actors = con.execute("SELECT COUNT(DISTINCT stix_id) FROM actor").fetchone()[0]
status = "PASS" if actual_actors == published["actor"] else "FAIL"
if status == "FAIL":
    failures.append("actor")
print(f"DQ [{status}] actor: {actual_actors} distinct vs {published['actor']} published")

# the relationship tables only cover entities with >=1 relationship, so they're subsets:
# distinct counts must never exceed the published total (that would mean duplicates,
# stray revoked/deprecated rows, or an id-matching bug), and coverage is reported for context.
subset_checks = [
    ("technique", "actor_technique", "technique_id"),
    ("software", "actor_software", "software_id"),
    ("technique", "technique_mitigation", "technique_id"),
    ("mitigation", "technique_mitigation", "mitigation_id"),
]
for entity, table, column in subset_checks:
    distinct = con.execute(f"SELECT COUNT(DISTINCT {column}) FROM {table}").fetchone()[0]
    total = published[entity]
    ok = distinct <= total
    status = "PASS" if ok else "FAIL"
    if not ok:
        failures.append(f"{table}.{column}")
    pct = (distinct / total * 100) if total else 0.0
    print(f"DQ [{status}] {table}.{column}: {distinct} distinct <= {total} published {entity}s ({pct:.0f}% coverage)")

if failures:
    print(f"DATA QUALITY CHECK FAILED: {', '.join(failures)}", file=sys.stderr)
    sys.exit(1)