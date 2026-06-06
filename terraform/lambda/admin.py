"""
Taxonomy Admin API — handles pending review, approve, reject.
Used by admin.html UI and taxonomy.sh CLI.
"""
import os, json, time, boto3
from boto3.dynamodb.conditions import Attr

cache_table = boto3.resource("dynamodb").Table(os.environ["CACHE_TABLE"])
s3 = boto3.client("s3")
BUCKET = os.environ["TAXONOMY_BUCKET"]
TAXONOMY_KEY = "taxonomy.json"


def load_taxonomy():
    try:
        obj = s3.get_object(Bucket=BUCKET, Key=TAXONOMY_KEY)
        return json.loads(obj["Body"].read())
    except s3.exceptions.NoSuchKey:
        return {"_meta": {}, "apps": {}}


def save_taxonomy(tax):
    tax["_meta"]["updated"] = time.strftime("%Y-%m-%d")
    s3.put_object(Bucket=BUCKET, Key=TAXONOMY_KEY, Body=json.dumps(tax, indent=2), ContentType="application/json")


def get_pending():
    """Scan cache table for pending items (not yet in taxonomy)."""
    resp = cache_table.scan(
        FilterExpression=Attr("status").eq("pending") | Attr("status").not_exists(),
        Limit=200,
    )
    return resp.get("Items", [])


def handler(event, ctx):
    qs = event.get("queryStringParameters") or {}
    action = qs.get("action", "pending")
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")

    # CORS preflight
    if method == "OPTIONS":
        return {"statusCode": 200, "headers": {"access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,OPTIONS", "access-control-allow-headers": "content-type"}, "body": ""}

    if action == "pending" and method == "GET":
        pending = get_pending()
        taxonomy = load_taxonomy()
        items = []
        for p in pending:
            items.append({
                "dest_key": p.get("dest_key", ""),
                "app": p.get("app", "unknown"),
                "category": p.get("category", "unknown"),
                "confidence": str(p.get("confidence", "0")),
                "reason": p.get("reason", ""),
                "seen_count": int(p.get("seen_count", 1)),
            })
        return respond({"pending": items, "taxonomy": taxonomy.get("apps", {})})

    if method == "POST":
        body = json.loads(event.get("body", "{}"))
        dest_key = body.get("dest_key", "")

        if action == "approve":
            app = body.get("app", "").strip().lower().replace(" ", "_")
            category = body.get("category", "unknown")
            if not app or not dest_key:
                return respond({"error": "app and dest_key required"}, 400)

            # Update cache entry to confirmed
            cache_table.update_item(
                Key={"dest_key": dest_key},
                UpdateExpression="SET app = :app, category = :cat, #s = :s, confirmed_at = :t",
                ExpressionAttributeValues={":app": app, ":cat": category, ":s": "confirmed", ":t": int(time.time())},
                ExpressionAttributeNames={"#s": "status"},
            )

            # Add to taxonomy in S3
            taxonomy = load_taxonomy()
            # Extract base domain from dest_key (e.g., "v2.circuit.edge.jazz:443" → "circuit.edge.jazz")
            pattern = dest_key.split(":")[0]
            if app in taxonomy["apps"]:
                if pattern not in taxonomy["apps"][app].get("patterns", []):
                    taxonomy["apps"][app]["patterns"].append(pattern)
            else:
                taxonomy["apps"][app] = {"category": category, "patterns": [pattern]}
            save_taxonomy(taxonomy)

            return respond({"message": f"Approved: {dest_key} → {app}"})

        if action == "reject":
            if not dest_key:
                return respond({"error": "dest_key required"}, 400)
            # Support search_by_app: find cache entries matching this app name
            if body.get("search_by_app"):
                resp = cache_table.scan(
                    FilterExpression=Attr("app").eq(dest_key),
                    Limit=50,
                )
                rejected = 0
                for item in resp.get("Items", []):
                    cache_table.update_item(
                        Key={"dest_key": item["dest_key"]},
                        UpdateExpression="SET #s = :s, rejected_at = :t",
                        ExpressionAttributeValues={":s": "rejected", ":t": int(time.time())},
                        ExpressionAttributeNames={"#s": "status"},
                    )
                    rejected += 1
                return respond({"message": f"Rejected {rejected} cache entries matching '{dest_key}'"})
            cache_table.update_item(
                Key={"dest_key": dest_key},
                UpdateExpression="SET #s = :s, rejected_at = :t",
                ExpressionAttributeValues={":s": "rejected", ":t": int(time.time())},
                ExpressionAttributeNames={"#s": "status"},
            )
            return respond({"message": f"Rejected: {dest_key}"})

    return respond({"error": "unknown action"}, 400)


def respond(body, code=200):
    return {
        "statusCode": code,
        "headers": {"content-type": "application/json", "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,OPTIONS"},
        "body": json.dumps(body, default=str),
    }
