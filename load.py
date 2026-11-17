import duckdb

con = duckdb.connect("flaws2.duckdb")

con.execute("""
    CREATE OR REPLACE TABLE events AS
    SELECT unnest(Records) AS r
    FROM read_json('data/AWSLogs/**/*.json.gz',
                   union_by_name=true,
                   maximum_object_size=104857600)
""")

print(con.execute("SELECT count(*) FROM events").fetchone())
print(con.execute("""
    SELECT r.eventName, count(*) AS n
    FROM events GROUP BY 1 ORDER BY n DESC LIMIT 15
""").fetchall())