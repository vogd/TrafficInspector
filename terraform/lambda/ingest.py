import os, time, json, uuid, boto3
from decimal import Decimal

logs = boto3.client("logs")
s3 = boto3.client("s3")
table = boto3.resource("dynamodb").Table(os.environ["TABLE"])
WINDOW = int(os.environ.get("WINDOW_MIN", "15"))
TTL = 7 * 86400
FLOW_COLS = ["srcaddr", "dstaddr", "srcport", "dstport", "protocol", "pkt-srcaddr",
             "pkt-dstaddr", "bytes", "packets", "action", "flow-direction", "start", "end",
             "tcp-flags", "type", "vpc-id", "subnet-id", "interface-id", "log-status",
             "traffic-path", "pkt-dst-aws-service", "pkt-src-aws-service"]


def q(group, limit=5000):
    end = int(time.time()); start = end - WINDOW * 60
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


def flatten(e, out, p=""):  # raw field names exactly as the source emits them (e.g. tls.sni, http.url, netflow.bytes)
    for k, v in e.items():
        if isinstance(v, dict):
            flatten(v, out, p + k + ".")
        elif isinstance(v, list):
            out[p + k] = json.dumps(v)[:1500]
        elif v not in (None, ""):
            out[p + k] = v


def coerce(v):
    return Decimal(str(v)) if isinstance(v, float) else v


# Only flag as threat if actually BLOCKED or hit by managed threat rules
THREAT_PREFIXES = ("BLOCK:", "Block ", "Trojan", "Malware", "Botnet", "C2", "Phishing", "Exploit")


def is_threat(item):
    action = item.get("alert.action", "")
    if action == "blocked":
        return True
    sig = item.get("alert.signature", "")
    for p in THREAT_PREFIXES:
        if sig.startswith(p):
            return True
    if item.get("aws_category", ""):
        return True
    return False


def handler(event, ctx):
    items = {}
    # AWS Network Firewall: merge alert + tls + netflow events by flow_id -> one raw record per connection
    for g in (os.environ["ALERT_LG"], os.environ["TLS_LG"], os.environ["NFW_FLOW_LG"]):
        for msg in q(g):
            try:
                o = json.loads(msg); e = o["event"]
            except Exception:
                continue
            if not e.get("src_ip"):
                continue
            cid = "nfw#" + str(e.get("flow_id") or f'{e["src_ip"]}:{e.get("src_port")}-{e.get("dest_ip")}:{e.get("dest_port")}')
            it = items.setdefault(cid, {"conn_id": cid, "gsipk": "all", "source": "NFW", "ts": 0})
            it["ts"] = max(it["ts"], int(o.get("event_timestamp") or time.time()))
            flatten(e, it)
    # VPC Flow Logs: one raw record per flow-log line
    now = int(time.time())
    for msg in q(os.environ["VPC_FLOW_LG"]):
        p = msg.split()
        if len(p) < len(FLOW_COLS):
            continue
        rec = dict(zip(FLOW_COLS, p))
        # Skip NODATA heartbeat records (all fields are '-')
        if rec.get("action", "-") == "-":
            continue
        # Skip 1-packet probes (internet background noise / port scans)
        if rec.get("packets", "0") in ("1", "0") and int(rec.get("bytes", "0") or 0) < 100:
            continue
        # Only keep flows involving spoke/VPN traffic (10.0.x.x or 10.20.x.x), skip internet→inspection probes
        pkt_src = rec.get("pkt-srcaddr", "")
        pkt_dst = rec.get("pkt-dstaddr", "")
        if not (pkt_src.startswith("10.0.") or pkt_src.startswith("10.20.") or pkt_dst.startswith("10.0.") or pkt_dst.startswith("10.20.")):
            continue
        fts = int(rec["start"]) if rec.get("start", "-").isdigit() else now
        cid = f'flow#{rec["srcaddr"]}:{rec["srcport"]}-{rec["dstaddr"]}:{rec["dstport"]}#{fts // 60}'
        it = {"conn_id": cid, "gsipk": "all", "source": "FlowLogs", "ts": fts}
        it.update({k: v for k, v in rec.items() if v != "-"})
        items[cid] = it
    with table.batch_writer(overwrite_by_pkeys=["conn_id"]) as bw:
        for it in items.values():
            it["ttl"] = it["ts"] + TTL
            if is_threat(it):
                it["threat"] = "true"
            # Copy NFW signature to ai_app for unified app name column
            sig = it.get("alert.signature", "")
            if sig and not it.get("ai_app"):
                it["ai_app"] = sig
                it["ai_confidence"] = "1.0"
                it["ai_category"] = "nfw_rule"
                it["ai_reason"] = "identified by NFW Suricata rule"
            bw.put_item(Item={k: coerce(v) for k, v in it.items() if v not in (None, "")})
    # Dual-write raw per-connection records to the S3 lake (date-partitioned NDJSON) for AI/analytics
    bucket = os.environ.get("LAKE_BUCKET")
    if bucket and items:
        body = "\n".join(json.dumps(it, default=str) for it in items.values())
        dt = time.strftime("%Y-%m-%d", time.gmtime())
        s3.put_object(Bucket=bucket, Key=f"connections/dt={dt}/{int(time.time())}-{uuid.uuid4().hex[:8]}.json", Body=body)
    return {"items": len(items)}
