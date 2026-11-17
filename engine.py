import yaml


def esc(v):
    return str(v).replace("'", "''")


def clause(field, value):
    name, _, modifier = field.partition("|")
    col = "r." + name
    values = value if isinstance(value, list) else [value]
    if modifier == "contains":
        parts = [f"{col} ILIKE '%{esc(v)}%'" for v in values]
    else:
        parts = [f"{col} ILIKE '{esc(v)}'" for v in values]
    return "(" + " OR ".join(parts) + ")"


def selection_sql(selection):
    return "(" + " AND ".join(clause(f, v) for f, v in selection.items()) + ")"


def load_rule(path):
    with open(path) as f:
        return yaml.safe_load(f)


def hits(con, rule):
    detection = rule["detection"]
    names = [n.strip() for n in detection["condition"].split(" and ")]
    where = " AND ".join(selection_sql(detection[n]) for n in names)
    sql = f"""
        SELECT CAST(r.eventTime AS VARCHAR) AS time,
               r.eventName,
               r.userIdentity.arn AS identity,
               r.sourceIPAddress AS ip
        FROM events
        WHERE {where}
        ORDER BY r.eventTime
    """
    return con.execute(sql).fetchall()