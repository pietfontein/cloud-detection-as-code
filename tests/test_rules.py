import glob
import os

import duckdb
import pytest

from engine import load_rule, hits

RULE_PATHS = sorted(glob.glob("rules/*.yml"))


def events_from(fixture):
    con = duckdb.connect(":memory:")
    con.execute(f"""
        CREATE TABLE events AS
        SELECT unnest(Records) AS r
        FROM read_json('{fixture}', union_by_name=true)
    """)
    return con


@pytest.mark.parametrize("path", RULE_PATHS)
def test_rule_matches_bad_events(path):
    name = os.path.splitext(os.path.basename(path))[0]
    con = events_from(f"tests/fixtures/{name}/should_match.json")
    assert len(hits(con, load_rule(path))) > 0


@pytest.mark.parametrize("path", RULE_PATHS)
def test_rule_ignores_good_events(path):
    name = os.path.splitext(os.path.basename(path))[0]
    con = events_from(f"tests/fixtures/{name}/should_not_match.json")
    assert hits(con, load_rule(path)) == []