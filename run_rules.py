import glob
import duckdb
from engine import load_rule, hits

con = duckdb.connect("flaws2.duckdb")
con.execute("SET TimeZone='UTC'")

for path in sorted(glob.glob("rules/*.yml")):
    rule = load_rule(path)
    found = hits(con, rule)
    print(f"\n{rule['title']}  [{rule['level']}]  ->  {len(found)} hit(s)")
    for hit in found:
        print("  ", hit)
from correlation_engine import load_correlation, correlate

for path in sorted(glob.glob("correlations/*.yml")):
    rule = load_correlation(path)
    found = correlate(con, rule)
    print(f"\n{rule['title']}  [{rule['level']}]  ->  {len(found)} hit(s)")
    for hit in found:
        print("  ", hit)