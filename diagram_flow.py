#!/usr/bin/env python3
"""TrafInspector traffic flow diagram — SVG output (fixed)."""

from diagrams import Diagram, Cluster, Edge
from diagrams.aws.network import (
    TransitGateway, NATGateway, InternetGateway,
    NetworkFirewall, ClientVpn, VPCFlowLogs, Route53,
    ElbNetworkLoadBalancer as NLB
)
from diagrams.aws.security import SecurityHub, Guardduty, ACM
from diagrams.aws.compute import Lambda, EC2
from diagrams.aws.storage import S3
from diagrams.aws.database import Dynamodb
from diagrams.aws.integration import Eventbridge, StepFunctions
from diagrams.aws.management import Cloudwatch
from diagrams.aws.ml import Bedrock
from diagrams.aws.analytics import Athena
from diagrams.generic.device import Mobile
from diagrams.onprem.network import Internet
from diagrams.onprem.client import User

FLOW = "orange"
LOG = "blue"
AI = "purple"
FUTURE = "gray"

with Diagram(
    "TrafInspector — Traffic Flow",
    filename="architecture-flow",
    outformat="svg",
    show=False,
    direction="LR",
    graph_attr={"fontsize": "13", "bgcolor": "white", "pad": "0.4",
                "nodesep": "0.6", "ranksep": "1.0"},
):
    # --- Sources ---
    with Cluster("① Device"):
        laptop = User("Managed\nLaptop")
        phone = Mobile("BYOD")

    # --- VPN ---
    vpn = ClientVpn("② Client VPN\n(full tunnel)")

    # --- Spoke ---
    with Cluster("③ Spoke VPC (10.1.0.0/16)"):
        ec2 = EC2("Test Client")

    # --- TGW ---
    tgw = TransitGateway("④ Transit GW\n(appliance mode)")

    # --- Inspection ---
    with Cluster("⑤ Inspection VPC (10.100.0.0/16)"):
        with Cluster("TGW Subnet → NFW"):
            nfw = NetworkFirewall("⑥ Network Firewall\nTLS decrypt (ACM CA)\nSuricata IPS\nQUIC blocked")
        with Cluster("FW Subnet → NAT"):
            nat = NATGateway("⑦ NAT GW")
        with Cluster("Public Subnet"):
            igw = InternetGateway("⑧ IGW")
        dns = Route53("DNS Firewall\n(log + block)")
        gwlb = NLB("GWLB slot\n(3rd-party future)")

    # --- Internet (generic icon, NOT CloudFront) ---
    internet = Internet("⑨ Internet\n(Zoom, Teams,\nSalesforce)")

    # --- Logs ---
    with Cluster("⑩ Telemetry Pipeline"):
        cw = Cloudwatch("CW Logs\nalert/tls/flow")
        flow = VPCFlowLogs("Flow Logs")
        ingest_fn = Lambda("Ingest λ")
        ddb = Dynamodb("DynamoDB\n(7d hot)")
        s3 = S3("S3 Lake\n(partitioned)")

    # --- AI & Security Analysis (reads logs, NOT inline) ---
    with Cluster("⑪ Security Analysis (reads logs, not inline)"):
        gd = Guardduty("GuardDuty\n(reads Flow Logs\n+ DNS logs →\nML threat findings)")
        hub = SecurityHub("Security Hub\n(aggregates\nfindings → ASFF)")
        eb = Eventbridge("EventBridge\n(routes findings)")

    with Cluster("⑫ AI Response"):
        bedrock = Bedrock("Bedrock Agent\n(triage + RCA\n+ rule-gen)")
        sfn = StepFunctions("Step Fn\n(auto-remediate)")

    # === TRAFFIC FLOW (orange) — the actual packet path ===
    laptop >> Edge(color=FLOW, style="bold", label="1. TLS 1.3") >> vpn
    phone >> Edge(color=FLOW, style="bold") >> vpn
    vpn >> Edge(color=FLOW, style="bold", label="2. tunnel\nterminates\nin spoke") >> ec2
    ec2 >> Edge(color=FLOW, style="bold", label="3. default route\n→ TGW") >> tgw
    tgw >> Edge(color=FLOW, style="bold", label="4. forward to\ninspection VPC") >> nfw
    nfw >> Edge(color=FLOW, style="bold", label="5. inspected +\nre-encrypted") >> nat
    nat >> Edge(color=FLOW, style="bold", label="6. SNAT\n(public IP)") >> igw
    igw >> Edge(color=FLOW, style="bold", label="7. egress to\npublic internet") >> internet

    # DNS sidecar
    nfw >> Edge(color="green", style="dashed", label="DNS queries") >> dns

    # GWLB future
    nfw >> Edge(color=FUTURE, style="dotted", label="future") >> gwlb

    # === LOG FLOW (blue) — NFW writes logs, Flow Logs captured ===
    nfw >> Edge(color=LOG, label="Suricata EVE\nJSON logs") >> cw
    nfw >> Edge(color=LOG) >> flow
    cw >> Edge(color=LOG) >> ingest_fn
    flow >> Edge(color=LOG) >> ingest_fn
    ingest_fn >> Edge(color=LOG) >> ddb
    ingest_fn >> Edge(color=LOG) >> s3

    # === ANALYSIS FLOW (purple) — reads logs, produces findings ===
    # GuardDuty reads Flow Logs + DNS (NOT inline, just analysis)
    flow >> Edge(color=AI, style="dashed", label="reads") >> gd
    dns >> Edge(color=AI, style="dashed", label="reads") >> gd
    gd >> Edge(color=AI, label="threat\nfindings") >> hub
    hub >> Edge(color=AI, label="ASFF\nevent") >> eb
    eb >> Edge(color=AI, label="trigger") >> bedrock
    eb >> Edge(color=AI) >> sfn

    # AI response back to NFW
    s3 >> Edge(color=AI, style="dashed") >> bedrock
    bedrock >> Edge(color=AI, label="new Suricata\nrule / block IP") >> nfw
    sfn >> Edge(color=AI, label="NACL update\nor quarantine") >> nfw
