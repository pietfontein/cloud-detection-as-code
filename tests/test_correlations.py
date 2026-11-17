import glob
import os

import duckdb
import pytest

from correlation_engine import load_correlation, correlate

PATHS = sorted(glob.glob("correlations/*.yml"))


def events_from(fixture):
    con = duckdb.connect(":memory:")
    con.execute("SET TimeZone='UTC'")
    con.execute(f"""
        CREATE TABLE events AS
        SELECT unnest(Records) AS r
        FROM read_json('{fixture}', union_by_name=true)
    """)
    return con


@pytest.mark.parametrize("path", PATHS)
def test_correlation_matches_bad_events(path):
    name = os.path.splitext(os.path.basename(path))[0]
    con = events_from(f"tests/fixtures/{name}/should_match.json")
    assert len(correlate(con, load_correlation(path))) > 0


@pytest.mark.parametrize("path", PATHS)
def test_correlation_ignores_good_events(path):
    name = os.path.splitext(os.path.basename(path))[0]
    con = events_from(f"tests/fixtures/{name}/should_not_match.json")
    assert correlate(con, load_correlation(path)) == []