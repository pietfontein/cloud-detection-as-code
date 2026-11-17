import ipaddress
import json
import os

import yaml

IPV4 = "'^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$'"


def esc(v):
    return str(v).replace("'", "''")


def _aws_networks():
    path = "data/aws-ip-ranges.json"
    if not os.path.exists(path):
        raise FileNotFoundError(
            "exclude_aws_ip_ranges is on but data/aws-ip-ranges.json is missing"
        )
    with open(path) as f:
        data = json.load(f)
    return [ipaddress.ip_network(p["ip_prefix"]) for p in data["prefixes"]]


def load_correlation(path):
    with open(path) as f:
        return yaml.safe_load(f)


def _multiple_ips(con, rule):
    window = int(rule["correlation"]["timespan_minutes"]) * 60
    sql = f"""
        WITH ev AS (
            SELECT r.userIdentity.arn AS arn,
                   r.sourceIPAddress  AS ip,
                   r.eventTime        AS t
            FROM events
            WHERE r.userIdentity.type = 'AssumedRole'
              AND regexp_matches(r.sourceIPAddress, {IPV4})
        )
        SELECT a.arn,
               a.ip AS ip_a,
               b.ip AS ip_b,
               CAST(min(least(a.t, b.t)) AS VARCHAR)    AS first_seen,
               CAST(max(greatest(a.t, b.t)) AS VARCHAR) AS last_seen
        FROM ev a
        JOIN ev b
          ON a.arn = b.arn
         AND a.ip < b.ip
         AND abs(epoch(a.t) - epoch(b.t)) <= {window}
        GROUP BY a.arn, a.ip, b.ip
        ORDER BY first_seen
    """
    return con.execute(sql).fetchall()


def _service_session(con, rule):
    c = rule["correlation"]
    max_age = int(c["max_age_minutes"]) * 60
    allow = c.get("known_egress_ips") or []
    allow_sql = ""
    if allow:
        listed = ", ".join("'" + esc(ip) + "'" for ip in allow)
        allow_sql = f"AND u.ip NOT IN ({listed})"
    sql = f"""
        WITH created AS (
            SELECT r.requestParameters.roleSessionName AS session_name,
                   r.requestParameters.roleArn         AS role_arn,
                   r.eventTime                         AS t
            FROM events
            WHERE r.eventName = 'AssumeRole'
              AND r.userIdentity.type = 'AWSService'
        ),
        used AS (
            SELECT r.userIdentity.arn   AS arn,
                   r.sourceIPAddress    AS ip,
                   r.eventName          AS event_name,
                   r.eventTime          AS t
            FROM events
            WHERE r.userIdentity.type = 'AssumedRole'
              AND regexp_matches(r.sourceIPAddress, {IPV4})
        )
        SELECT c.role_arn,
               c.session_name,
               u.ip,
               u.event_name,
               CAST(c.t AS VARCHAR) AS issued,
               CAST(u.t AS VARCHAR) AS used_at
        FROM created c
        JOIN used u
          ON u.arn = 'arn:aws:sts::' || split_part(c.role_arn, ':', 5)
                     || ':assumed-role/' || string_split(c.role_arn, '/')[-1]
                     || '/' || c.session_name
         AND epoch(u.t) >= epoch(c.t)
         AND epoch(u.t) - epoch(c.t) <= {max_age}
         {allow_sql}
        ORDER BY u.t
    """
    rows = con.execute(sql).fetchall()
    if c.get("exclude_aws_ip_ranges"):
        nets = _aws_networks()
        rows = [
            r for r in rows
            if not any(ipaddress.ip_address(r[2]) in n for n in nets)
        ]
    return rows


HANDLERS = {
    "multiple_ips": _multiple_ips,
    "service_session": _service_session,
}


def correlate(con, rule):
    kind = rule["correlation"].get("type", "multiple_ips")
    return HANDLERS[kind](con, rule)