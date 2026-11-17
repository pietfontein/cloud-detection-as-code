import duckdb

con = duckdb.connect("flaws2.duckdb")
con.execute("SET TimeZone='UTC'")

rows = con.execute("""
    SELECT
        r.userIdentity.arn                AS identity,
        count(DISTINCT r.sourceIPAddress) AS ip_count,
        list(DISTINCT r.sourceIPAddress)  AS ips,
        list(DISTINCT r.userAgent)        AS agents
    FROM events
    WHERE r.userIdentity.type = 'AssumedRole'
    GROUP BY 1
    ORDER BY ip_count DESC
""").fetchall()

for row in rows:
    print(row)