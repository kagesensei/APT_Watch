import datetime
import io
import tarfile

import duckdb
import sigma

from conftest import FIXTURES_DIR


def _build_fixture_tarball() -> tarfile.TarFile:
    """Build an in-memory tar.gz mirroring SigmaHQ/sigma's layout (rule
    files under a "sigma-master/" wrapper directory) from the small YAML
    files under tests/fixtures/sigma_rules/ -- never a live download.
    """
    fixtures_root = FIXTURES_DIR / "sigma_rules"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in sorted(fixtures_root.rglob("*.yml")):
            arcname = "sigma-master/" + str(path.relative_to(fixtures_root)).replace("\\", "/")
            tar.add(path, arcname=arcname)
    buf.seek(0)
    return tarfile.open(fileobj=buf, mode="r:gz")


class TestDatedFilename:
    def test_includes_the_iso_date(self):
        assert sigma.dated_filename(datetime.date(2026, 9, 14)) == "sigma_2026-09-14.tar.gz"


class TestTagStrings:
    def test_extracts_tags_as_strings(self):
        rule = {"tags": ["attack.t1055", "attack.g0007"]}
        assert sigma._tag_strings(rule) == ["attack.t1055", "attack.g0007"]

    def test_missing_tags_returns_empty_list(self):
        assert sigma._tag_strings({}) == []

    def test_non_list_tags_returns_empty_list(self):
        assert sigma._tag_strings({"tags": "not-a-list"}) == []


class TestExtractIds:
    def test_technique_tags_uppercased_and_sorted(self):
        tags = ["attack.credential-access", "attack.t1003.001", "attack.t1055", "attack.g0007"]
        assert sigma._extract_ids(tags, sigma.TECHNIQUE_TAG_RE) == ["T1003.001", "T1055"]

    def test_actor_tags(self):
        tags = ["attack.g0007", "attack.t1055"]
        assert sigma._extract_ids(tags, sigma.ACTOR_TAG_RE) == ["G0007"]

    def test_case_insensitive_and_deduplicated(self):
        tags = ["ATTACK.T1055", "attack.t1055"]
        assert sigma._extract_ids(tags, sigma.TECHNIQUE_TAG_RE) == ["T1055"]

    def test_tactic_and_software_tags_are_not_matched(self):
        tags = ["attack.collection", "attack.s0002", "attack.ds0005"]
        assert sigma._extract_ids(tags, sigma.TECHNIQUE_TAG_RE) == []
        assert sigma._extract_ids(tags, sigma.ACTOR_TAG_RE) == []


class TestRuleDirOf:
    def test_included_dir(self):
        assert sigma._rule_dir_of("sigma-master/rules/windows/foo.yml") == "rules"

    def test_skipped_dir(self):
        assert sigma._rule_dir_of("sigma-master/deprecated/foo.yml") == "deprecated"

    def test_unrelated_dir_returns_none(self):
        assert sigma._rule_dir_of("sigma-master/documentation/foo.yml") is None

    def test_top_level_file_returns_none(self):
        assert sigma._rule_dir_of("sigma-master/README.md") is None


class TestParseTarball:
    def test_walks_included_dirs_and_skips_deprecated_unsupported(self):
        with _build_fixture_tarball() as tar:
            parsed = sigma.parse_tarball(tar, "2026-09-14")

        # rules/: with_tags, no_tags, malformed (3) + deprecated/old_rule (1)
        # + unsupported/bad_rule (1) = 5. other/not_a_rule.yml is not
        # rule-shaped at all and must never be counted.
        assert parsed["walked"] == 5
        assert parsed["skipped_reasons"] == {"deprecated": 1, "unsupported": 1, "unparseable": 1}
        assert len(parsed["rule_rows"]) == 2

    def test_technique_and_actor_tags_extracted(self):
        with _build_fixture_tarball() as tar:
            parsed = sigma.parse_tarball(tar, "2026-09-14")
        rule_id = "aaaaaaaa-1111-2222-3333-444444444444"
        assert (rule_id, "T1003.001") in parsed["technique_rows"]
        assert (rule_id, "T1055") in parsed["technique_rows"]
        assert (rule_id, "G0007") in parsed["actor_rows"]

    def test_rule_with_no_tags_is_counted_and_uncovered(self):
        with _build_fixture_tarball() as tar:
            parsed = sigma.parse_tarball(tar, "2026-09-14")
        rule_id = "bbbbbbbb-1111-2222-3333-444444444444"
        assert any(r[0] == rule_id for r in parsed["rule_rows"])
        assert not any(r[0] == rule_id for r in parsed["technique_rows"])
        assert parsed["no_technique_tag_count"] == 1

    def test_logsource_fields_default_to_none_when_absent(self):
        with _build_fixture_tarball() as tar:
            parsed = sigma.parse_tarball(tar, "2026-09-14")
        row = next(
            r for r in parsed["rule_rows"] if r[0] == "bbbbbbbb-1111-2222-3333-444444444444"
        )
        assert row[4] is None  # logsource.category absent in the fixture
        assert row[5] == "azure"  # logsource.product present

    def test_source_url_is_built_from_the_repo_relative_file_path(self):
        with _build_fixture_tarball() as tar:
            parsed = sigma.parse_tarball(tar, "2026-09-14")
        row = next(
            r for r in parsed["rule_rows"] if r[0] == "aaaaaaaa-1111-2222-3333-444444444444"
        )
        assert row[7] == "rules/test_rule_with_tags.yml"
        assert row[8] == (
            "https://github.com/SigmaHQ/sigma/blob/master/rules/test_rule_with_tags.yml"
        )


class TestCheckParsedCount:
    def test_passes_when_matching(self):
        con = duckdb.connect(":memory:")
        with _build_fixture_tarball() as tar:
            parsed = sigma.parse_tarball(tar, "2026-09-14")
        sigma.write_tables(
            con, parsed["rule_rows"], parsed["technique_rows"], parsed["actor_rows"]
        )
        skipped_total = sum(parsed["skipped_reasons"].values())
        assert sigma.check_parsed_count(con, parsed["walked"], skipped_total) is None

    def test_fails_when_mismatched(self):
        con = duckdb.connect(":memory:")
        with _build_fixture_tarball() as tar:
            parsed = sigma.parse_tarball(tar, "2026-09-14")
        sigma.write_tables(
            con, parsed["rule_rows"], parsed["technique_rows"], parsed["actor_rows"]
        )
        assert sigma.check_parsed_count(con, parsed["walked"], 0) == "sigma_rule row count"
