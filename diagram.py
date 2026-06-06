#!/usr/bin/env python3
"""TrafInspector architecture diagram using the `diagrams` Python library."""

from diagrams import Diagram, Cluster, Edge
from diagrams.aws.network import (
    VPC, TransitGateway, NATGateway, InternetGateway,
    NetworkFirewall, ClientVpn, VPCFlowLogs, Route53,
    CloudFront, ElbNetworkLoadBalancer as NLB
)
from diagrams.aws.security import (
    SecurityHub, Guardduty, Detective, Shield, WAF,
    Macie, Inspector, ACM, SecretsManager
)
from diagrams.aws.compute import Lambda, EC2
from diagrams.aws.storage import S3
from diagrams.aws.database import Dynamodb
from diagrams.aws.integration import Eventbridge, StepFunctions, SQS
from diagrams.aws.management import Cloudwatch
from diagrams.aws.ml import Bedrock, Sagemaker
from diagrams.aws.analytics import Athena
from diagrams.generic.device import Mobile, Tablet
from diagrams.onprem.client import User

graph_attr = {
    "fontsize": "14",
    "bgcolor": "white",
    "pad": "0.5",
    "nodesep": "0.8",
    "ranksep": "1.2",
}

with Diagram(
    "TrafInspector — Traffic Inspection & AI Security",
    filename="architecture",
    outformat="png",
    show=False,
    direction="TB",
    graph_attr=graph_attr,
):
    # --- Devices ---
    with Cluster("End Devices"):
        laptop = User("Managed\nDevice")
        byod = Mobile("BYOD")

    # --- Ingress ---
    vpn = ClientVpn("AWS Client VPN\n(full tunnel)")

    # --- Spoke VPC ---
    with Cluster("Spoke VPC"):
        client_ec2 = EC2("Test Client\n(traffic-gen)")
        spoke_rt = Route53("Spoke RT\n0.0.0.0/0→TGW")

    # --- Transit Gateway ---
    tgw = TransitGateway("Transit Gateway\n(appliance mode)")

    # --- Inspection VPC ---
    with Cluster("Inspection VPC (2-AZ)"):
        with Cluster("Security Inspection"):
            nfw = NetworkFirewall("AWS Network\nFirewall\n(TLS decrypt +\nSuricata IPS)")
            dns_fw = Route53("DNS Firewall\n(query logging)")

        with Cluster("Egress Path"):
            nat = NATGateway("NAT Gateway")
            igw = InternetGateway("IGW")

        with Cluster("3rd-Party Slot"):
            gwlb = NLB("GWLB\n(Palo Alto /\nHPE SSE)")

        acm_ca = ACM("ACM CA\n(TLS MITM cert)")

    # --- Logging & Analytics ---
    with Cluster("Telemetry & Data Lake"):
        cw_logs = Cloudwatch("CloudWatch Logs\n(NFW alert/tls/flow)")
        flow_logs = VPCFlowLogs("VPC Flow Logs")
        ingest = Lambda("Ingest Lambda\n(1-min)")
        ddb = Dynamodb("DynamoDB\n(hot store, 7d TTL)")
        lake = S3("S3 Data Lake\n(NDJSON + Parquet)")

    # --- UI ---
    cf = CloudFront("CloudFront UI\n(live dashboard)")
    query_fn = Lambda("Query Lambda\n(Function URL)")

    # --- AI / Security Orchestration ---
    with Cluster("AI-Driven Security Loop"):
        bedrock = Bedrock("Bedrock Agent\n(Claude — triage,\nRCA, rule-gen)")
        sagemaker = Sagemaker("SageMaker\n(behavioral ML)")
        athena = Athena("Athena\n(S3 lake queries)")

    with Cluster("Security Services"):
        guardduty = Guardduty("GuardDuty\n(threat detection)")
        sec_hub = SecurityHub("Security Hub\n(findings agg)")
        detective = Detective("Detective\n(graph analysis)")
        eventbridge = Eventbridge("EventBridge\n(event bus)")
        step_fn = StepFunctions("Step Functions\n(auto-remediate)")

    # --- Flows ---
    # Device → VPN → Spoke
    laptop >> Edge(label="VPN tunnel") >> vpn
    byod >> Edge(label="VPN tunnel") >> vpn
    vpn >> spoke_rt
    client_ec2 >> spoke_rt

    # Spoke → TGW → Inspection
    spoke_rt >> Edge(label="all egress") >> tgw
    tgw >> Edge(label="inspect") >> nfw
    nfw >> nat >> igw

    # TLS & DNS
    acm_ca >> Edge(style="dashed", label="signs certs") >> nfw
    nfw >> Edge(style="dashed", label="DNS queries") >> dns_fw

    # GWLB (future)
    nfw >> Edge(style="dotted", label="future: inline") >> gwlb

    # Logging
    nfw >> Edge(label="alert/tls/flow") >> cw_logs
    nfw >> flow_logs
    cw_logs >> ingest
    flow_logs >> ingest
    ingest >> ddb
    ingest >> lake

    # UI
    cf >> query_fn >> ddb

    # AI tier
    lake >> athena
    athena >> bedrock
    lake >> sagemaker
    bedrock >> Edge(label="MCP tools") >> nfw

    # Security orchestration
    guardduty >> sec_hub
    nfw >> Edge(style="dashed", label="findings") >> sec_hub
    sec_hub >> eventbridge
    eventbridge >> bedrock
    eventbridge >> step_fn
    bedrock >> Edge(label="investigate") >> detective
    step_fn >> Edge(label="remediate") >> nfw
