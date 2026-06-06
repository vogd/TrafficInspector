#!/usr/bin/env python3
"""TrafInspector — Full Architecture: inspection + classification + taxonomy."""

from diagrams import Diagram, Cluster, Edge
from diagrams.aws.network import (
    TransitGateway, NATGateway, InternetGateway,
    NetworkFirewall, ClientVpn, VPCFlowLogs, Route53,
    ElbNetworkLoadBalancer as NLB, CloudFront
)
from diagrams.aws.security import SecurityHub, Guardduty, ACM
from diagrams.aws.compute import Lambda
from diagrams.aws.storage import S3
from diagrams.aws.database import Dynamodb
from diagrams.aws.integration import Eventbridge, SNS
from diagrams.aws.management import Cloudwatch
from diagrams.aws.ml import Bedrock
from diagrams.aws.analytics import Athena
from diagrams.onprem.network import Internet
from diagrams.onprem.client import User
from diagrams.generic.device import Mobile

FLOW = "#e65100"  # orange - traffic
LOG = "#1565c0"   # blue - logs
AI = "#7b1fa2"    # purple - AI
STORE = "#2e7d32"  # green - storage
ALERT = "#c62828"  # red - alerts

with Diagram(
    "TrafInspector — Full Architecture",
    filename="architecture-full",
    outformat="png",
    show=False,
    direction="LR",
    graph_attr={"fontsize": "11", "bgcolor": "white", "pad": "0.8",
                "nodesep": "1.2", "ranksep": "1.5", "compound": "true",
                "splines": "polyline"},
    node_attr={"width": "1.2", "height": "1.2", "fontsize": "10"},
    edge_attr={"minlen": "2"},
):
    # --- Devices ---
    with Cluster("End Devices"):
        laptop = User("Managed\nDevice")
        phone = Mobile("BYOD")

    vpn = ClientVpn("AWS Client VPN\n(full tunnel)")

    # --- Spoke VPC ---
    with Cluster("Spoke VPC (10.0.0.0/16)"):
        spoke_rt = Route53("Route: 0.0.0.0/0\n→ TGW")

    # --- TGW ---
    tgw = TransitGateway("Transit Gateway\n(appliance mode)")

    # --- Inspection VPC ---
    with Cluster("INSPECTION VPC (10.100.0.0/16) — DEPLOYED"):
        nfw = NetworkFirewall("Network Firewall\n98 rules + 9 managed\nTLS decrypt (MITM)\nP2P/Tor DROP")
        acm = ACM("ACM CA")
        nat = NATGateway("NAT GW")
        igw = InternetGateway("IGW")
        flow_logs = VPCFlowLogs("VPC Flow Logs\n(all fields)")
        gwlb = NLB("GWLB slot\n(3rd-party future\nnot deployed)")

    internet = Internet("Internet")

    # --- Logging ---
    with Cluster("Log Collection"):
        cw = Cloudwatch("CloudWatch Logs\n/nfw/alert\n/nfw/tls\n/nfw/flow\n/flowlogs")

    # --- Ingest + Hot Store ---
    with Cluster("Data Pipeline"):
        ingest_fn = Lambda("Ingest Lambda\n(1 min schedule)\nmerges by flow_id\nfilters probes\nsets ai_app from rules")
        ddb = Dynamodb("DynamoDB\n(hot store)\n7-day TTL\nconn_id key\nGSI: by_time")
        ddb_cache = Dynamodb("DynamoDB\n(classification cache)\n30-day TTL\ndest_key → app")

    # --- Data Lake ---
    with Cluster("Data Lake (S3)"):
        lake = S3("S3 Lake\nconnections/ NDJSON\nvpcflow/ Parquet\ntaxonomy.json\n(partitioned)")
        athena = Athena("Athena\n(query lake)")

    # --- AI Classification ---
    with Cluster("AI Classification (every 5 min)"):
        classifier = Lambda("Classifier Lambda\ndedup → cache → batch\nSonnet 4.6\nfull-stream context\nanomaly detection")
        bedrock = Bedrock("Bedrock\nClaude Sonnet 4.6\n(15 items/batch)")

    # --- Taxonomy Admin ---
    with Cluster("Taxonomy Management"):
        admin_fn = Lambda("Admin Lambda\napprove/reject/rename")
        admin_ui = CloudFront("Admin UI\n/admin.html\napprove ✓ reject ✗")
        taxonomy = S3("taxonomy.json\n(canonical names)\nsource of truth")

    # --- Alerting ---
    with Cluster("Alerting"):
        sns = SNS("SNS\ntrafinspector-alerts")
        cw_alarm = Cloudwatch("CW Metric Filter\n+ Alarm\n(blocked traffic)")

    # --- Live UI ---
    ui = CloudFront("Live UI\nCloudFront\nfilters: blocked/\ndetected/AI/unclassified")
    query_fn = Lambda("Query Lambda\nserver-side filter\npagination")

    # === TRAFFIC FLOW ===
    laptop >> Edge(color=FLOW, style="bold", label="1") >> vpn
    phone >> Edge(color=FLOW, style="bold") >> vpn
    vpn >> Edge(color=FLOW, style="bold", label="2") >> spoke_rt
    spoke_rt >> Edge(color=FLOW, style="bold", label="3") >> tgw
    tgw >> Edge(color=FLOW, style="bold", label="4") >> nfw
    acm >> Edge(style="dashed") >> nfw
    nfw >> Edge(color=FLOW, style="bold", label="5") >> nat
    nfw >> Edge(color="gray", style="dotted", label="future") >> gwlb
    nat >> Edge(color=FLOW, style="bold", label="6") >> igw
    igw >> Edge(color=FLOW, style="bold", label="7") >> internet

    # === LOG FLOW ===
    nfw >> Edge(color=LOG, label="alert/tls/flow") >> cw
    flow_logs >> Edge(color=LOG, label="all fields") >> cw
    cw >> Edge(color=LOG) >> ingest_fn
    ingest_fn >> Edge(color=LOG) >> ddb
    ingest_fn >> Edge(color=STORE) >> lake

    # === AI CLASSIFICATION ===
    ddb >> Edge(color=AI, label="unclassified\nitems") >> classifier
    classifier >> Edge(color=AI, label="check") >> ddb_cache
    ddb_cache >> Edge(color=AI, style="dashed", label="cache\nhit") >> classifier
    classifier >> Edge(color=AI, label="unknown\ndestinations") >> bedrock
    bedrock >> Edge(color=AI, label="app + confidence\n+ category") >> classifier
    classifier >> Edge(color=AI, label="write\nai_app") >> ddb
    classifier >> Edge(color=AI, label="cache\nnew") >> ddb_cache

    # === TAXONOMY ===
    ddb_cache >> Edge(color=AI, style="dashed") >> admin_fn
    admin_fn >> Edge(color=STORE, label="approve") >> taxonomy
    admin_fn >> Edge(color=AI) >> ddb_cache
    admin_ui >> Edge(color=AI) >> admin_fn
    taxonomy >> Edge(color=AI, style="dashed", label="load on\ncold start") >> classifier

    # === ALERTING ===
    cw >> Edge(color=ALERT, label="blocked\nevents") >> cw_alarm
    cw_alarm >> Edge(color=ALERT) >> sns

    # === UI ===
    ui >> Edge(color=LOG) >> query_fn
    query_fn >> Edge(color=LOG) >> ddb

    # === ATHENA ===
    lake >> Edge(color=STORE, style="dashed", label="SQL\nqueries") >> athena
