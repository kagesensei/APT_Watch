"""Ingest SigmaHQ/sigma detection rules -- and their ATT&CK technique/actor
tag references -- into data/cti.duckdb.

Downloads a tarball snapshot of the repo (no git executable required) and
reads rule YAML files directly out of the archive; nothing is extracted to
disk beyond the tarball itself.

The rule directory list and YAML shape below were determined by inspecting
a real download, not assumed: SigmaHQ/sigma's default branch is "master"
(not "main"), it has 8 rule-shaped top-level directories, and of the 3783
rule files across the 6 included ones, "logsource.category" is absent on
830, "logsource.product" absent on 169, and "tags" absent on 2 -- id,
title, status, level, and description were present on all of them, but are
still read defensively.
"""

import datetime
import re
import tarfile
from typing import IO, TypedDict

import common
import duckdb
import yaml

from contracts import precondition

URL = "https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master"
BLOB_BASE = "https://github.com/SigmaHQ/sigma/blob/master"

# Every top-level directory in the repo that holds detection rules.
# 'rules-dfir' is real but, in the snapshot this was written against,
# empty (just a README). Excluded per the task: 'deprecated' (superseded
# rules) and 'unsupported' (rules SigmaHQ no longer maintains support
# claims for) -- both still counted in "walked", both reported as skipped.
INCLUDED_RULE_DIRS = (
    "rules", "rules-compliance", "rules-dfir", "rules-emerging-threats",
    "rules-placeholder", "rules-threat-hunting",
)
SKIPPED_RULE_DIRS = ("deprecated", "unsupported")

TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
ACTOR_TAG_RE = re.compile(r"^attack\.(g\d{4})$", re.IGNORECASE)

SigmaRuleRow = tuple[str, str, str, str, str | None, str | None, str, str, str, str]
TechniqueTagRow = tuple[str, str]
ActorTagRow = tuple[str, str]


class ParsedRules(TypedDict):
    """Everything one ingest run needs to write tables and report on."""

    rule_rows: list[SigmaRuleRow]
    technique_rows: list[TechniqueTagRow]
    actor_rows: list[ActorTagRow]
    walked: int
    skipped_reasons: dict[str, int]
    no_technique_tag_count: int


def dated_filename(today: datetime.date) -> str:
    """A dated filename for the downloaded tarball, e.g. sigma_2026-09-14.tar.gz."""
    return f"sigma_{today.isoformat()}.tar.gz"


def _tag_strings(rule: dict[str, object]) -> list[str]:
    tags = rule.get("tags")
    if not isinstance(tags, list):
        return []
    return [str(t) for t in tags]


def _extract_ids(tags: list[str], pattern: re.Pattern[str]) -> list[str]:
    ids = set()
    for tag in tags:
        match = pattern.match(tag)
        if match:
            ids.add(match.group(1).upper())
    return sorted(ids)


def _rule_dir_of(member_name: str) -> str | None:
    """The top-level rule directory a tar member falls under, e.g. 'rules',
    or None if it isn't inside any rule-shaped directory at all (docs,
    tests, images -- never part of the walk).
    """
    parts = member_name.split("/", 2)
    if len(parts) < 3:
        return None
    top_dir = parts[1]
    if top_dir in INCLUDED_RULE_DIRS or top_dir in SKIPPED_RULE_DIRS:
        return top_dir
    return None


def _parse_one_rule(
    extracted: IO[bytes], file_path: str, retrieved: str
) -> tuple[SigmaRuleRow, list[str]] | None:
    """Parse one rule file's bytes into a sigma_rule row plus its raw tag
    list, or None if it can't be parsed as a Sigma rule.
    """
    try:
        rule = yaml.safe_load(extracted.read())
    except yaml.YAMLError:
        return None
    if not isinstance(rule, dict):
        return None
    rule_id = rule.get("id")
    if not rule_id:
        return None

    logsource = rule.get("logsource") or {}
    source_url = f"{BLOB_BASE}/{file_path}"
    row: SigmaRuleRow = (
        str(rule_id),
        str(rule.get("title", "")),
        str(rule.get("status", "")),
        str(rule.get("level", "")),
        logsource.get("category"),
        logsource.get("product"),
        str(rule.get("description", "")),
        file_path,
        source_url,
        retrieved,
    )
    return row, _tag_strings(rule)


def parse_tarball(tar: tarfile.TarFile, retrieved: str) -> ParsedRules:
    """Walk every rules-shaped directory in the tarball, skipping
    deprecated/unsupported, parsing everything else.
    """
    rule_rows: list[SigmaRuleRow] = []
    technique_rows: list[TechniqueTagRow] = []
    actor_rows: list[ActorTagRow] = []
    walked = 0
    skipped_reasons: dict[str, int] = {}
    no_technique_tag_count = 0

    for member in tar.getmembers():
        if not member.isfile() or not member.name.endswith(".yml"):
            continue
        rule_dir = _rule_dir_of(member.name)
        if rule_dir is None:
            continue
        walked += 1
        if rule_dir in SKIPPED_RULE_DIRS:
            skipped_reasons[rule_dir] = skipped_reasons.get(rule_dir, 0) + 1
            continue

        extracted = tar.extractfile(member)
        if extracted is None:
            skipped_reasons["unreadable"] = skipped_reasons.get("unreadable", 0) + 1
            continue

        # Drop the tarball's own "sigma-master/" wrapper directory.
        file_path = "/".join(member.name.split("/")[1:])
        parsed = _parse_one_rule(extracted, file_path, retrieved)
        if parsed is None:
            skipped_reasons["unparseable"] = skipped_reasons.get("unparseable", 0) + 1
            continue

        row, tags = parsed
        rule_rows.append(row)
        rule_id = row[0]
        technique_ids = _extract_ids(tags, TECHNIQUE_TAG_RE)
        if not technique_ids:
            no_technique_tag_count += 1
        technique_rows.extend((rule_id, tid) for tid in technique_ids)
        actor_rows.extend((rule_id, gid) for gid in _extract_ids(tags, ACTOR_TAG_RE))

    return {
        "rule_rows": rule_rows,
        "technique_rows": technique_rows,
        "actor_rows": actor_rows,
        "walked": walked,
        "skipped_reasons": skipped_reasons,
        "no_technique_tag_count": no_technique_tag_count,
    }


def write_tables(
    con: duckdb.DuckDBPyConnection,
    rule_rows: list[SigmaRuleRow],
    technique_rows: list[TechniqueTagRow],
    actor_rows: list[ActorTagRow],
) -> None:
    """Create (or replace) and populate sigma_rule, sigma_rule_technique,
    and sigma_rule_actor.
    """
    con.execute(
        "CREATE OR REPLACE TABLE sigma_rule("
        "rule_id VARCHAR, title VARCHAR, status VARCHAR, level VARCHAR, "
        "logsource_category VARCHAR, logsource_product VARCHAR, description VARCHAR, "
        "file_path VARCHAR, source_url VARCHAR, retrieved DATE)"
    )
    con.executemany("INSERT INTO sigma_rule VALUES (?,?,?,?,?,?,?,?,?,?)", rule_rows)

    con.execute(
        "CREATE OR REPLACE TABLE sigma_rule_technique(rule_id VARCHAR, technique_id VARCHAR)"
    )
    con.executemany("INSERT INTO sigma_rule_technique VALUES (?,?)", technique_rows)

    con.execute("CREATE OR REPLACE TABLE sigma_rule_actor(rule_id VARCHAR, attack_id VARCHAR)")
    con.executemany("INSERT INTO sigma_rule_actor VALUES (?,?)", actor_rows)


def check_parsed_count(con: duckdb.DuckDBPyConnection, walked: int, skipped: int) -> str | None:
    """sigma_rule's row count must equal walked minus skipped. Returns a
    failure name, or None.
    """
    precondition(walked >= 0 and skipped >= 0, "walked and skipped must be non-negative")
    expected = walked - skipped
    actual = common.table_count(con, "sigma_rule")
    status = "PASS" if actual == expected else "FAIL"
    print(
        f"DQ [{status}] sigma_rule: {actual} loaded vs "
        f"{walked} walked - {skipped} skipped = {expected}"
    )
    return None if status == "PASS" else "sigma_rule row count"


def main() -> None:
    """Fetch, ingest, and data-quality-check the SigmaHQ/sigma rule set."""
    today = datetime.datetime.now(datetime.timezone.utc).date()
    raw_path = common.fetch(URL, dated_filename(today))
    retrieved = today.isoformat()

    # parse_tarball() only reads member metadata (tar.getmembers()) and
    # member content in-memory (tar.extractfile()) -- it never writes a file
    # to a path taken from the archive, so the path-traversal risk B202
    # warns about (a member escaping the extraction directory) doesn't apply
    # here; there is no extraction directory.
    with tarfile.open(raw_path, mode="r:gz") as tar:  # nosec B202
        parsed = parse_tarball(tar, retrieved)

    con = duckdb.connect(str(common.DB_PATH))
    write_tables(con, parsed["rule_rows"], parsed["technique_rows"], parsed["actor_rows"])
    common.print_table_counts(con, ["sigma_rule", "sigma_rule_technique", "sigma_rule_actor"])

    skipped_total = sum(parsed["skipped_reasons"].values())
    print(f"Walked {parsed['walked']} rule YAML files; skipped {skipped_total}:")
    for reason, count in sorted(parsed["skipped_reasons"].items()):
        print(f"  {reason}: {count}")
    print(f"Rules with no attack.t* technique tag: {parsed['no_technique_tag_count']}")

    failure = check_parsed_count(con, parsed["walked"], skipped_total)
    common.fail_if_any([failure] if failure else [])


if __name__ == "__main__":
    main()
