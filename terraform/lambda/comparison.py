import os, time, json, html, boto3

logs = boto3.client("logs")
s3 = boto3.client("s3")


def q(group, minutes=30, limit=3000):
    end = int(time.time()); start = end - minutes * 60
    try:
        qid = logs.start_query(logGroupName=group, startTime=start, endTime=end,
                               queryString=f"fields @message | sort @timestamp desc | limit {limit}")["queryId"]
    except logs.exceptions.ResourceNotFoundException:
        return []
    while True:
        r = logs.get_query_results(queryId=qid)
        if r["status"] in ("Complete", "Failed", "Cancelled"):
            break
        time.sleep(1)
    return [next((f["value"] for f in row if f["field"] == "@message"), "") for row in r.get("results", [])]


def k_of(e):
    return (e["src_ip"], e.get("dest_ip"), str(e.get("src_port")), str(e.get("dest_port")), e.get("proto") or "TCP")


def put(rec, key, val):
    if val and not rec.get(key):
        rec[key] = val


THREAT_SIGS = ("Evasion:", "VPN:", "P2P:", "Trojan", "Malware", "Botnet", "C2", "Phishing", "Exploit")


def handler(event, ctx):
    rows = {}
    for g in (os.environ["ALERT_LG"], os.environ["TLS_LG"]):
        for msg in q(g):
            try:
                e = json.loads(msg)["event"]
            except Exception:
                continue
            if not e.get("src_ip"):
                continue
            http, tls, alert = e.get("http", {}), e.get("tls", {}), e.get("alert", {})
            host = http.get("hostname") or next((h["value"] for h in http.get("request_headers", []) if h.get("name") == ":authority"), None)
            rec = rows.setdefault(k_of(e), {})
            put(rec, "sni", tls.get("sni") or e.get("sni"))
            put(rec, "app", e.get("app_proto"))
            put(rec, "host", host)
            put(rec, "sig", alert.get("signature"))
            put(rec, "cat", e.get("aws_category"))
            if alert.get("action") == "blocked" or any(str(alert.get("signature","")).startswith(p) for p in THREAT_SIGS) or e.get("aws_category"):
                rec["threat"] = "true"
            put(rec, "method", http.get("http_method"))
            put(rec, "url", http.get("url"))
            put(rec, "ua", http.get("http_user_agent"))
            put(rec, "status", http.get("status"))
            put(rec, "ctype", http.get("http_content_type"))
            put(rec, "tlsver", tls.get("version"))
            put(rec, "subject", tls.get("subject"))
            put(rec, "issuer", tls.get("issuerdn"))
    for msg in q(os.environ["FLOW_LG"]):
        try:
            e = json.loads(msg)["event"]
        except Exception:
            continue
        key = k_of(e)
        if key in rows:
            nf = e.get("netflow", {})
            rows[key]["bytes"] = rows[key].get("bytes", 0) + nf.get("bytes", 0)
            rows[key]["pkts"] = rows[key].get("pkts", 0) + nf.get("pkts", 0)
    app = {k: v for k, v in rows.items() if not str(v.get("sni") or v.get("host") or "").endswith("amazonaws.com")}
    s3.put_object(Bucket=os.environ["BUCKET"], Key="index.html",
                  Body=render(app, len(rows) - len(app)), ContentType="text/html")
    return {"app_connections": len(app), "hidden_controlplane": len(rows) - len(app)}


# (source label, column count, header color, cell tint)
GROUPS = [("VPC Flow Logs (metadata)", 7, "#7fc99a", "#e8f7ee"),
          ("AWS Network Firewall (application layer, decrypted)", 13, "#8db8f0", "#eaf2ff"),
          ("3rd-party appliance (not native)", 2, "#e89b9b", "#fbeaea")]
COLS = ["src_ip", "dst_ip", "src_port", "dst_port", "proto", "bytes", "pkts",
        "Application", "SNI", "app_proto", "matched rule", "category", "method", "url",
        "user-agent", "http status", "content-type", "TLS ver", "cert subject", "cert issuer",
        "JA3/JA4", "Palo Alto (App-ID/User-ID/DLP)"]
FIVE = {"src_ip", "dst_ip", "src_port", "dst_port", "proto"}


def render(rows, hidden):
    hdr_bg, cell_bg = [], []
    for _, n, h, c in GROUPS:
        hdr_bg += [h] * n; cell_bg += [c] * n
    grp = "".join(f'<th colspan={n} style="background:{h}">{name}</th>' for name, n, h, c in GROUPS)
    cols = "".join(f'<th style="background:{"#fde68a" if c in FIVE else hdr_bg[i]}">{c}</th>' for i, c in enumerate(COLS))
    trs = ""
    for (s, d, sp, dp, pr), v in sorted(rows.items(), key=lambda kv: (kv[1].get("sni") or kv[1].get("host") or "~")):
        row_bg = "background:#fee2e2;" if v.get("threat") else ""
        vals = [s, d, sp, dp, pr, v.get("bytes"), v.get("pkts"),
                v.get("sni") or v.get("host"), v.get("sni"), v.get("app"), v.get("sig"), v.get("cat"),
                v.get("method"), v.get("url"), v.get("ua"), v.get("status"), v.get("ctype"),
                v.get("tlsver"), v.get("subject"), v.get("issuer"),
                "n/a (not emitted by NFW)", "pending — no appliance"]
        tds = "".join(f'<td style="{row_bg}background:{"#fde68a" if COLS[i] in FIVE else cell_bg[i] if not row_bg else ""}">{html.escape(str(x if x not in (None, "") else "-"))}</td>' for i, x in enumerate(vals))
        trs += f"<tr>{tds}</tr>"
    style = "<style>body{font:13px sans-serif}table{border-collapse:collapse}th,td{border:1px solid #ccc;padding:4px;white-space:nowrap;text-align:center}</style>"
    return (f"<html><head><meta charset=utf-8><title>Visibility by AWS service</title>{style}</head><body>"
            f"<h2>Per-connection visibility — which service sees what</h2>"
            f"<p>{len(rows)} app connections · {hidden} AWS control-plane flows hidden. "
            f"Top row = data source. Amber = the 5-tuple (connection identity; also visible to NFW). "
            f"Flow Logs = metadata only; Network Firewall adds the application layer; JA3/App-ID/DLP need a 3rd-party appliance.</p>"
            f"<table><tr>{grp}</tr><tr>{cols}</tr>{trs}</table></body></html>")
