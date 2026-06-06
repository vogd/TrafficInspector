import os, json, time, boto3
from boto3.dynamodb.conditions import Key, Attr

table = boto3.resource("dynamodb").Table(os.environ["TABLE"])
RANGES = {"5m": 300, "15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
PAGE_SIZE = 1000


def build_filter(flt, source_filter):
    """Build FilterExpression using raw DynamoDB expressions to handle dot-separated attribute names."""
    expr_parts = []
    expr_names = {}
    expr_values = {}

    if flt == "threats":
        expr_parts.append("(#aa = :blocked OR #thr = :true)")
        expr_names["#aa"] = "alert.action"
        expr_names["#thr"] = "threat"
        expr_values[":blocked"] = "blocked"
        expr_values[":true"] = "true"
    elif flt == "detected":
        expr_parts.append("(attribute_exists(#asig) AND (#aa = :allowed OR attribute_not_exists(#aa)))")
        expr_names["#asig"] = "alert.signature"
        expr_names["#aa"] = "alert.action"
        expr_values[":allowed"] = "allowed"
    elif flt == "ai":
        expr_parts.append("(attribute_exists(#aiapp) AND #aiapp <> :unclass AND #aiapp <> :dash AND #aicat <> :nfwrule)")
        expr_names["#aiapp"] = "ai_app"
        expr_names["#aicat"] = "ai_category"
        expr_values[":unclass"] = "unclassified"
        expr_values[":dash"] = "-"
        expr_values[":nfwrule"] = "nfw_rule"
    elif flt == "unclassified":
        expr_parts.append("(attribute_not_exists(#asig) AND (attribute_not_exists(#aiapp) OR #aiapp = :unclass))")
        expr_names["#asig"] = "alert.signature"
        expr_names["#aiapp"] = "ai_app"
        expr_values[":unclass"] = "unclassified"

    if source_filter:
        expr_parts.append("#src = :srcval")
        expr_names["#src"] = "source"
        expr_values[":srcval"] = source_filter

    if not expr_parts:
        return None, None, None
    return " AND ".join(expr_parts), expr_names, expr_values


def handler(event, ctx):
    qs = event.get("queryStringParameters") or {}
    cutoff = int(time.time()) - RANGES.get(qs.get("range", "15m"), 900)
    offset = int(qs.get("offset", "0"))
    source_filter = qs.get("source", "")
    flt = qs.get("filter", "")

    filter_expr, expr_names, expr_values = build_filter(flt, source_filter)

    items, lek = [], None
    fetch_limit = offset + PAGE_SIZE
    while len(items) < fetch_limit:
        kw = dict(
            IndexName="by_time",
            KeyConditionExpression=Key("gsipk").eq("all") & Key("ts").gte(cutoff),
            ScanIndexForward=False,
            Limit=1000,
        )
        if filter_expr:
            kw["FilterExpression"] = filter_expr
            if expr_names:
                kw["ExpressionAttributeNames"] = expr_names
            if expr_values:
                kw["ExpressionAttributeValues"] = expr_values
        if lek:
            kw["ExclusiveStartKey"] = lek
        r = table.query(**kw)
        items += r["Items"]
        lek = r.get("LastEvaluatedKey")
        if not lek:
            break

    total = len(items)
    page = items[offset:offset + PAGE_SIZE]
    has_more = (offset + PAGE_SIZE) < total

    return {"statusCode": 200, "headers": {"content-type": "application/json"},
            "body": json.dumps({"count": len(page), "total": total, "offset": offset, "has_more": has_more, "items": page}, default=str)}
