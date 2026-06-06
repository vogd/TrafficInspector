#!/usr/bin/env python3
"""Taxonomy classification pipeline — how it learns and becomes deterministic."""

from diagrams import Diagram, Cluster, Edge
from diagrams.aws.compute import Lambda
from diagrams.aws.storage import S3
from diagrams.aws.database import Dynamodb
from diagrams.aws.ml import Bedrock
from diagrams.aws.network import CloudFront
from diagrams.aws.integration import SNS
from diagrams.onprem.client import User

AI = "#7b1fa2"
STORE = "#2e7d32"
ALERT = "#c62828"
CACHE = "#1565c0"

with Diagram(
    "Taxonomy — Learning & Deterministic Classification",
    filename="architecture-taxonomy",
    outformat="png",
    show=False,
    direction="LR",
    graph_attr={"fontsize": "11", "bgcolor": "white", "pad": "0.8",
                "nodesep": "1.2", "ranksep": "1.5"},
    node_attr={"width": "1.2", "height": "1.2", "fontsize": "10"},
    edge_attr={"minlen": "2"},
):
    # --- Input ---
    with Cluster("New Traffic (unclassified)"):
        ddb = Dynamodb("DynamoDB\n(connections)\nno alert.signature\nno ai_app")

    # --- Cache Check ---
    with Cluster("Classification Cache (DynamoDB)"):
        cache = Dynamodb("Cache Table\ndest_key → app\nstatus: pending/\nconfirmed/rejected\n30-day TTL")

    # --- AI Classification ---
    with Cluster("AI Tier (Bedrock)"):
        classifier = Lambda("Classifier\n(every 5 min)\ndedup by dest\nbatch 15 items")
        bedrock = Bedrock("Claude Sonnet 4.6\nfull-stream context\nanomaly detection\nentropy analysis")

    # --- Taxonomy Source of Truth ---
    with Cluster("Taxonomy (deterministic)"):
        taxonomy = S3("taxonomy.json\n(S3)\ncanonical app names\npatterns per app\ngit-versioned")

    # --- Admin Review ---
    with Cluster("Human Review"):
        admin_ui = CloudFront("Admin UI\n/admin.html")
        admin_fn = Lambda("Admin Lambda\napprove ✓\nreject ✗\nrename →")
        reviewer = User("Security\nAdmin")

    # --- Notification ---
    sns = SNS("SNS Alert\n'N new pending\nclassifications'")

    # === FLOW: New traffic enters ===
    ddb >> Edge(color=AI, label="① query\nunclassified") >> classifier

    # === FLOW: Cache check ===
    classifier >> Edge(color=CACHE, label="② check\ncache") >> cache
    cache >> Edge(color=CACHE, style="dashed", label="HIT:\nuse cached app\n(deterministic)") >> classifier

    # === FLOW: Cache miss → Bedrock ===
    classifier >> Edge(color=AI, label="③ MISS:\nsend to AI") >> bedrock
    bedrock >> Edge(color=AI, label="④ app +\nconfidence +\ncategory") >> classifier

    # === FLOW: Write results ===
    classifier >> Edge(color=STORE, label="⑤ write\nai_app") >> ddb
    classifier >> Edge(color=CACHE, label="⑥ cache as\n'pending'") >> cache

    # === FLOW: Notify ===
    cache >> Edge(color=ALERT, label="⑦ new\npending") >> sns
    sns >> Edge(color=ALERT) >> reviewer

    # === FLOW: Human review ===
    reviewer >> Edge(color=STORE, label="⑧ review") >> admin_ui
    admin_ui >> Edge(color=STORE) >> admin_fn
    admin_fn >> Edge(color=STORE, label="⑨ approve →\nstatus=confirmed") >> cache
    admin_fn >> Edge(color=STORE, label="⑩ update\ntaxonomy.json") >> taxonomy

    # === FLOW: Taxonomy feeds back ===
    taxonomy >> Edge(color=STORE, style="dashed", label="cold start:\nload patterns") >> classifier
