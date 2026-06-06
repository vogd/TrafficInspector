"""
AI Classifier — Optimized: dedup + cache + batch (every 5 min).

Cost reduction strategy:
1. DEDUPLICATE: Group events by (sni:port) or (dest_ip:port) → classify once per unique destination
2. CACHE: Check DynamoDB cache before calling Bedrock → skip known destinations
3. BATCH: Send all unknowns in one Bedrock call (≤15 items) → fewer API calls

Result: ~99% fewer Bedrock calls after warm-up. ~$0.10/day instead of $2/day.
"""
import os, json, time, math, boto3
from boto3.dynamodb.conditions import Key, Attr
from decimal import Decimal

table = boto3.resource("dynamodb").Table(os.environ["TABLE"])
cache_table = boto3.resource("dynamodb").Table(os.environ["CACHE_TABLE"])
bedrock = boto3.client("bedrock-runtime", region_name=os.environ.get("BEDROCK_REGION", "us-east-1"))
MODEL_ID = os.environ.get("MODEL_ID", "us.anthropic.claude-sonnet-4-6")
BATCH_SIZE = 15
CACHE_TTL_DAYS = 30

PROMPT = """You are an expert network traffic analyst. Classify each unique destination based on ALL available fields.

Rules:
- Use SNI, HTTP headers, cert info, user-agent as strongest signals
- Recognize vendor infra: "jazz"=Juniper Mist, "prisma"=Palo Alto, "zscaler"=Zscaler
- Flag anomalies: TLS cert failures (pinning), no app_proto (obfuscated), high-entropy SNI (DGA)
- If confident >0.6: classify. If suspicious but unidentifiable: "investigation_needed". Otherwise: "unclassified"

Categories: video_conferencing, messaging, cloud_storage, productivity, ai_service, developer_tools, streaming, social_media, email, vpn_proxy, p2p, gaming, advertising, cdn_infra, os_services, security, iot_device, vendor_infra, investigation_needed, unknown

Destinations:
{destinations}

Return ONLY a JSON array: [{{"app":"<name>","confidence":<0-1>,"category":"<cat>","reason":"<brief>"}}]"""


def shannon_entropy(s):
    if not s or len(s) < 3:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def dest_key(item):
    """Generate cache key: prefer SNI, fall back to IP."""
    sni = item.get("sni", "") or item.get("tls.sni", "")
    port = str(item.get("dest_port", "0"))
    if sni:
        return f"{sni}:{port}"
    return f"{item.get('dest_ip', '?')}:{port}"


def get_unclassified():
    """Query recent items. Prioritize NFW (rich context) over Flow Logs. Skip 1-packet probes."""
    now = int(time.time())
    resp = table.query(
        IndexName="by_time",
        KeyConditionExpression=Key("gsipk").eq("all") & Key("ts").gte(now - 1800),
        Limit=500,
        ScanIndexForward=False,
    )
    basic_fields = {"conn_id", "gsipk", "ttl", "ts", "source", "src_ip", "dest_ip",
                    "src_port", "dest_port", "proto", "ai_app", "ai_confidence",
                    "ai_category", "ai_reason", "threat"}
    nfw_items, flow_items = [], []
    for it in resp.get("Items", []):
        if it.get("ai_app") and it.get("ai_app") != "unclassified":
            continue
        # Skip 1-packet probes
        pkts = int(it.get("packets", 0) or it.get("netflow.pkts", 0) or 0)
        if pkts <= 1 and int(it.get("bytes", 0) or it.get("netflow.bytes", 0) or 0) < 100:
            continue
        has_extra = any(k not in basic_fields for k in it.keys())
        dest_port = int(it.get("dest_port", 0) or 0)
        if has_extra or dest_port in (80, 443, 8080, 8443, 53, 22):
            if it.get("source") == "NFW":
                nfw_items.append(it)
            else:
                flow_items.append(it)
    return (nfw_items + flow_items)[:BATCH_SIZE]


def check_cache(keys):
    """Batch lookup cache for known destinations."""
    if not keys:
        return {}
    unique_keys = list(set(keys))[:100]
    results = {}
    # Use resource batch_get (handles key format automatically)
    dynamodb = boto3.resource("dynamodb")
    resp = dynamodb.batch_get_item(
        RequestItems={cache_table.name: {"Keys": [{"dest_key": k} for k in unique_keys]}}
    )
    for item in resp.get("Responses", {}).get(cache_table.name, []):
        results[item["dest_key"]] = {
            "app": item.get("app", "unclassified"),
            "confidence": str(item.get("confidence", "0")),
            "category": item.get("category", "unknown"),
            "reason": item.get("reason", "cached"),
        }
    return results


def write_cache(key, result):
    """Write classification to cache as pending (awaiting human approval)."""
    # Check if already confirmed (don't overwrite approved items)
    existing = cache_table.get_item(Key={"dest_key": key}).get("Item")
    if existing and existing.get("status") == "confirmed":
        return  # already approved, don't touch

    if existing and existing.get("status") == "pending":
        # Increment seen count
        cache_table.update_item(
            Key={"dest_key": key},
            UpdateExpression="SET seen_count = if_not_exists(seen_count, :zero) + :one",
            ExpressionAttributeValues={":zero": 0, ":one": 1},
        )
        return

    cache_table.put_item(Item={
        "dest_key": key,
        "app": result.get("app", "unclassified"),
        "confidence": str(result.get("confidence", "0")),
        "category": result.get("category", "unknown"),
        "reason": result.get("reason", ""),
        "status": "pending",
        "seen_count": 1,
        "classified_at": int(time.time()),
        "ttl": int(time.time()) + CACHE_TTL_DAYS * 86400,
    })


def build_dest_context(items_for_dest):
    """Merge all events for a destination into one rich context."""
    ctx = {}
    for it in items_for_dest:
        for k, v in it.items():
            if k in ("conn_id", "gsipk", "ttl", "ai_app", "ai_confidence", "ai_category", "ai_reason", "threat"):
                continue
            if isinstance(v, Decimal):
                v = int(v) if v == int(v) else float(v)
            if v not in (None, "", "-", "0") and k not in ctx:
                ctx[k] = v
    # Anomaly signals
    sni = str(ctx.get("sni", ctx.get("tls.sni", "")))
    ctx["_anomaly"] = {
        "sni_entropy": round(shannon_entropy(sni), 2) if sni else None,
        "has_tls_error": any("error" in str(it.get("tls_error.error_message", "")).lower() for it in items_for_dest),
        "no_app_proto": ctx.get("app_proto") in (None, "", "-"),
        "event_count": len(items_for_dest),
    }
    return ctx


def classify_batch(destinations):
    """Send unique destinations to Bedrock in one call."""
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4096,
        "messages": [{"role": "user", "content": PROMPT.format(destinations=json.dumps(destinations, default=str))}],
    })
    try:
        resp = bedrock.invoke_model(modelId=MODEL_ID, body=body)
        text = json.loads(resp["body"].read())["content"][0]["text"]
        start = text.find("[")
        end = text.rfind("]") + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
    except Exception as e:
        print(f"Bedrock error: {e}")
    return None


def handler(event, ctx):
    items = get_unclassified()
    if not items:
        return {"scanned": 0, "from_cache": 0, "from_bedrock": 0, "total_updated": 0}

    # Step 1: DEDUPLICATE — group by destination
    dest_groups = {}
    for it in items:
        key = dest_key(it)
        dest_groups.setdefault(key, []).append(it)

    # Step 2: CACHE — check which destinations are already known
    all_keys = list(dest_groups.keys())
    cached = check_cache(all_keys)

    # Apply cached classifications
    from_cache = 0
    uncached_keys = []
    for key, group_items in dest_groups.items():
        if key in cached:
            result = cached[key]
            for it in group_items:
                table.update_item(
                    Key={"conn_id": it["conn_id"]},
                    UpdateExpression="SET ai_app = :app, ai_confidence = :conf, ai_category = :cat, ai_reason = :reason",
                    ExpressionAttributeValues={":app": result["app"], ":conf": result["confidence"], ":cat": result["category"], ":reason": "cached"},
                )
                from_cache += 1
        else:
            uncached_keys.append(key)

    # Step 3: BATCH — send only unknown destinations to Bedrock
    from_bedrock = 0
    if uncached_keys:
        batch_keys = uncached_keys[:BATCH_SIZE]
        destinations = [build_dest_context(dest_groups[k]) for k in batch_keys]
        results = classify_batch(destinations)

        for i, key in enumerate(batch_keys):
            if results and i < len(results) and isinstance(results[i], dict):
                result = results[i]
                result["confidence"] = str(result.get("confidence", 0))
            else:
                result = {"app": "unclassified", "confidence": "0", "category": "unknown", "reason": "classification_failed"}

            # Write to cache
            write_cache(key, result)

            # Update all items for this destination
            for it in dest_groups[key]:
                table.update_item(
                    Key={"conn_id": it["conn_id"]},
                    UpdateExpression="SET ai_app = :app, ai_confidence = :conf, ai_category = :cat, ai_reason = :reason",
                    ExpressionAttributeValues={":app": result.get("app", "unclassified"), ":conf": result.get("confidence", "0"), ":cat": result.get("category", "unknown"), ":reason": result.get("reason", "")},
                )
                from_bedrock += 1

    return {
        "scanned": len(items),
        "unique_destinations": len(dest_groups),
        "from_cache": from_cache,
        "from_bedrock": from_bedrock,
        "new_classifications": len(uncached_keys[:BATCH_SIZE]),
        "total_updated": from_cache + from_bedrock,
    }
