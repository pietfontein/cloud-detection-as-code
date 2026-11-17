import duckdb

con = duckdb.connect("flaws2.duckdb")

rows = con.execute("""
    SELECT
        r.eventTime,
        r.eventName,
        r.eventSource,
        r.userIdentity.type  AS identity_type,
        r.userIdentity.arn   AS identity_arn,
        r.sourceIPAddress    AS ip,
        r.userAgent          AS agent
    FROM events
    ORDER BY r.eventTime
""").fetchall()

for row in rows:
    print(row)