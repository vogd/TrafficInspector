# Traffic Inspection POC — Formal Deliverable

**Customer:** Aruba / HPE Networking
**Date:** 2026-06-01
**AWS Team:** Solutions Architecture
**Status:** POC Complete — Ready for Review

---

## Executive Summary

This document maps Aruba's traffic inspection requirements (Q1–Q5) to a working AWS-native POC
that demonstrates centralized TLS decryption, deep packet inspection, and application identification
— offloading inspection from edge devices to AWS with zero client-side proxy.

---

## 1. Architecture

### 1.1 Deployed POC (Outbound Inspection)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          CUSTOMER DEVICES                                        │
│                                                                                 │
│  Laptop/Mobile ──── AWS Client VPN (full tunnel) ────┐                          │
│  Managed Device ─── SD-WAN / IPsec ──────────────────┤  (Aruba pushes CA cert   │
│  IoT / Unmanaged ── Site-to-Site VPN ────────────────┤   to trusted devices)    │
└──────────────────────────────────────────────────────┼──────────────────────────┘
                                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         SPOKE VPC (per site/region)                              │
│  VPN termination subnet ── route table: 0.0.0.0/0 → TGW                        │
└──────────────────────────────────────────────────────┼──────────────────────────┘
                                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    TRANSIT GATEWAY (appliance mode = flow symmetry)              │
│                                                                                 │
│  Spoke RT: 0.0.0.0/0 → inspection attachment                                   │
│  Inspection RT: spoke CIDRs → spoke attachment; VPN CIDR → spoke attachment     │
└──────────────────────────────────────────────────────┼──────────────────────────┘
                                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         INSPECTION VPC (centralized)                             │
│                                                                                 │
│  ┌─── AZ-a ───────────────────────┐  ┌─── AZ-b ───────────────────────┐        │
│  │ TGW subnet → NFW endpoint (a)  │  │ TGW subnet → NFW endpoint (b)  │        │
│  │ FW subnet  → NAT GW (a)        │  │ FW subnet  → NAT GW (b)        │        │
│  │ Public subnet → IGW             │  │ Public subnet → IGW             │        │
│  └─────────────────────────────────┘  └─────────────────────────────────┘        │
│                                                                                 │
│  AWS Network Firewall:                                                          │
│  ├─ TLS Inspection (MITM via ACM CA) — decrypts all outbound :443              │
│  ├─ Suricata stateful rules (app detection, IPS, domain filtering)             │
│  ├─ QUIC blocked → forces TLS fallback for inspectability                      │
│  └─ Logs: alert (L7) + tls (handshake) + flow (netflow) → CloudWatch          │
│                                                                                 │
│  [GWLB endpoint service — 3rd-party appliance slot, no appliance yet]          │
└──────────────────────────────────────────────────────┼──────────────────────────┘
                                                       ▼
                                              NAT Gateway → IGW → Internet

┌─────────────────────────────────────────────────────────────────────────────────┐
│                         ANALYTICS / TELEMETRY                                    │
│                                                                                 │
│  NFW Logs + VPC Flow Logs → Ingest Lambda (1-min) → DynamoDB (hot, 7d TTL)     │
│                           → S3 Lake (NDJSON + Parquet, partitioned)             │
│                                                                                 │
│  Query Lambda (Function URL) ← CloudFront Static UI (time-range + source)      │
│                                                                                 │
│  [Future: Athena + SageMaker + Bedrock for AI classification]                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Future State (Bidirectional + 3rd-Party)

```
                    Inbound (App → Device)
                           │
                    ┌──────▼──────┐
                    │   GWLB      │ ← Palo Alto VM-Series / HPE SSE containers
                    │  (inline)   │    App-ID, User-ID, WildFire, DLP
                    └──────┬──────┘
                           │
              ┌────────────▼────────────────┐
              │  AWS Network Firewall        │ ← native TLS + IPS (always-on baseline)
              └────────────┬────────────────┘
                           │
                    Transit Gateway
                           │
                    Spoke VPC → Device
```

---

## 2. Requirement Mapping

### Q1: Workflow & Rules

| Aruba Requirement | POC Implementation | Status |
|---|---|---|
| Intent-based routing ("inspect App X") | TGW route table steers ALL egress to NFW; Suricata rules define per-app actions | ✅ Working |
| AIE application signatures | Suricata `tls.sni` + `content` rules detect apps (Zoom, Teams); extensible to any SNI/domain pattern | ✅ Working |
| Encryption handling (decrypt TLS 1.3) | NFW TLS Inspection Configuration with ACM CA; decrypts 0.0.0.0/0:443 | ✅ Working |
| Dynamic routing (device capacity < threshold) | TGW routing is unconditional in POC; Aruba edge can selectively route via SD-WAN policy | ✅ Architecture supports |
| Policy enforcement (block/allow per app) | Suricata `drop` / `alert` / `pass` actions per rule | ✅ Working |
| QUIC handling | `drop udp any any -> any 443` forces TLS fallback | ✅ Working |

**Decision logic mapping:**
```
Aruba's intent:                          AWS implementation:
─────────────────────────────────────────────────────────────────
IF device_capacity < threshold           SD-WAN/Aruba routes to AWS VPN
  OR encrypted_action_needed             (always true for TLS 1.3 deep inspect)
THEN route_to_aws_inspection       →     TGW → NFW (automatic via route table)
  IF HPE_SSE_available             →     GWLB → HPE containers (future)
  ELSE use_aws_network_firewall    →     NFW endpoint (current)
```

### Q2: Current Inspection Gaps Solved

| Edge Limitation | AWS Solution |
|---|---|
| Performance bottleneck (TLS decrypt on AP/GW) | NFW handles 100 Gbps/endpoint with TLS — zero edge load |
| Partial visibility (fragmented identity) | Centralized NFW sees ALL flows: SNI + HTTP + cert + netflow |
| Encrypted traffic blind spots | Full TLS 1.3 decryption via MITM (CA trusted on devices) |
| Static IP-based rules | Application-aware Suricata rules (SNI, domain, HTTP content) |
| No centralized app identity | Single inspection point correlates all sessions |

### Q3: Scope — Outbound ✅

Exactly what's deployed: Device → VPN/SD-WAN → Spoke VPC → TGW → NFW → Internet.

### Q4: Inbound — Architecture Ready

- GWLB endpoint service deployed (no appliance yet)
- Return-path routing configured for VPN client CIDR
- Phase 2 (Q3 2026): register Palo Alto/HPE appliance behind GWLB for inbound DPI

### Q5: Encryption/Decryption Flow

```
OUTBOUND (Device → App):
  Device encrypts (TLS 1.3) → VPN tunnel → Spoke → TGW → NFW
    NFW terminates TLS (ACM CA) → decrypts → DPI (Suricata) → re-encrypts → NAT → App

INBOUND (App → Device):  [Future]
  App response (TLS) → IGW → GWLB → Appliance decrypts → inspects → re-encrypts → TGW → Device

AUTHENTICATION:
  - Device trusts inspection CA (Aruba pushes cert via MDM, same as current AOS workflow)
  - VPN: mutual certificate auth (client cert + server cert, both signed by same CA)
  - No proxy on client — transparent routing via TGW
```

---

## 3. NFW Scaling & Capacity Limits

### 3.1 Per-Endpoint Throughput

| Metric | Limit | Adjustable? |
|---|---|---|
| **Bandwidth per firewall endpoint** | **100 Gbps** | ❌ No |
| TLS inspection bandwidth per endpoint | **100 Gbps** (same — no penalty) | ❌ No |
| Firewalls per account per region | 5 | ✅ Yes |
| Firewall endpoints per firewall | 1 per AZ (1 per subnet) | — |
| Stateful rules per policy | 30,000 (adjustable to 50,000) | ✅ Yes |

**Key insight:** NFW is a **managed service that auto-scales horizontally** behind each endpoint.
The 100 Gbps limit is per-endpoint, and you get one endpoint per AZ. AWS internally scales
the Suricata fleet behind the endpoint — you don't manage instances.

### 3.2 Is NFW a Bottleneck?

**Short answer: No, for Aruba's use case.**

| Scenario | Traffic Volume | NFW Capacity (2-AZ) | Headroom |
|---|---|---|---|
| POC (1 VPN client) | < 1 Gbps | 200 Gbps (2 endpoints) | 200x |
| Pilot (100 devices, 50 Mbps each) | 5 Gbps | 200 Gbps | 40x |
| Production (10K devices, 10 Mbps avg) | 100 Gbps | 200 Gbps | 2x |
| Large enterprise (50K devices) | 500 Gbps | Need 3+ AZs or multi-region | Scale-out needed |

### 3.3 Scaling Strategy for High Traffic

```
                    ┌─────────── Scale-Out Options ───────────┐
                    │                                          │
  Option A:         │  Option B:              Option C:        │
  More AZs          │  Multiple firewalls     Multi-region     │
  (same VPC)        │  (parallel VPCs)        (geo-split)      │
                    │                                          │
  3 AZs = 300 Gbps │  5 firewalls × 2 AZ    US + EU + APAC   │
  (us-east-2 has 3) │  = 1 Tbps              each with NFW    │
                    │                                          │
                    └──────────────────────────────────────────┘
```

**Option A — Add AZs (simplest):**
- us-east-2 has 3 AZs → 3 endpoints = 300 Gbps
- Just add a subnet + endpoint in the 3rd AZ
- TGW appliance mode ensures flow symmetry

**Option B — Multiple firewalls (same region):**
- Deploy separate inspection VPCs with their own NFW
- TGW routes different spoke CIDRs to different inspection VPCs
- 5 firewalls × 2 AZ = 1 Tbps capacity
- Adds operational complexity

**Option C — Multi-region (for global deployment):**
- Each region has its own inspection VPC + NFW
- Aruba routes devices to nearest region via SD-WAN/DNS
- Matches Aruba's "region-specific policies" requirement (Q1)
- Best for latency-sensitive inspection

### 3.4 What You Do NOT Need

- ❌ More subnets within the same AZ (1 NFW endpoint per AZ is the model)
- ❌ Manual instance scaling (NFW auto-scales behind the endpoint)
- ❌ Capacity reservations (NFW is fully on-demand)

### 3.5 Comparison: AWS Internal Migration Case Study

AWS migrated their own internal traffic to NFW:
- **10+ Tbps** of traffic
- **250 billion+ daily connections**
- **90% reduction** in networking tickets vs hardware firewalls

This validates NFW at scales far beyond Aruba's projected needs.

---

## 4. Per-Connection Visibility Delivered

| Field | Source | Decryption Required? |
|---|---|---|
| 5-tuple (IPs, ports, proto) | NFW + Flow Logs | No |
| SNI (server name) | NFW TLS log | No |
| TLS version, cipher, cert chain | NFW TLS log | No |
| HTTP host, URL, method, user-agent | NFW alert log | **Yes** (TLS decrypt) |
| Application protocol (http2, dns, etc.) | NFW flow log | No |
| Bytes, packets, duration per flow | NFW flow + Flow Logs | No |
| Suricata rule match (app tag) | NFW alert log | No |
| Domain category | NFW alert (managed rules) | No |
| Original device IP (behind NAT/TGW) | Flow Logs `pkt-srcaddr` | No |

**Not available natively (3rd-party upgrade path):**
- JA3/JA4 fingerprints (Palo Alto / custom Suricata build)
- App-ID sub-functions (Palo Alto)
- User-ID (Palo Alto + AD integration)
- WildFire sandboxing, DLP

---

## 5. Cost Model

| Component | $/month (2-AZ, us-east-2) |
|---|---|
| NFW endpoints (2 AZ) | $568.80 |
| NFW TLS Advanced Inspection (2 AZ) | $704.16 |
| TGW attachments (spoke + inspection) | $72.00 |
| NAT Gateway (hourly) | waived (chained) |
| Data processing (NFW $0.065/GB + TGW $0.04/GB) | **$0.105/GB** |
| Analytics (DDB + S3 + Lambda + CloudFront) | ~$20 |
| **Fixed total** | **≈ $1,450/mo** |

**At scale:** marginal cost converges to **$0.105/GB** inspected. TLS inspection adds no per-GB charge.

---

## 6. Deliverables Checklist

| # | Deliverable | Status |
|---|---|---|
| 1 | Working TLS decryption + DPI on outbound traffic | ✅ Live |
| 2 | Application detection (Zoom, Teams, Chrome, torrent) | ✅ Live |
| 3 | Per-connection visibility UI (CloudFront) | ✅ Live |
| 4 | VPN ingress for real device testing | ✅ Live |
| 5 | S3 data lake for AI/ML substrate | ✅ Live |
| 6 | GWLB scaffold for 3rd-party appliance | ✅ Ready |
| 7 | Native vs 3rd-party field comparison | ✅ Documented |
| 8 | Scaling analysis & limits | ✅ This document |
| 9 | AI classification tier (Bedrock/SageMaker) | 🔲 Phase 2 |
| 10 | Inbound inspection via GWLB | 🔲 Phase 2 |

---

## 7. Next Steps

1. **Customer review** of this deliverable + live UI demo
2. **CA distribution test** — Aruba pushes inspection CA to managed devices via AOS/MDM
3. **Rule expansion** — map Aruba's AIE app signatures to Suricata rules
4. **3rd-party pilot** — register HPE SSE or Palo Alto behind GWLB
5. **AI tier** — Athena + Bedrock over S3 lake for behavioral classification

---

## Appendix: Live Environment

| Resource | Value |
|---|---|
| Region | us-east-2 |
| CloudFront UI | <CLOUDFRONT_UI_URL>/index.html |
| Query API | <QUERY_FUNCTION_URL> |
| Client VPN | <VPN_ENDPOINT_ID> |
| NFW | trafinspector-fw |
| TGW | <TGW_ID> |
| Run rate | ~$2.0/hr |
| Teardown | `cd terraform && AWS_PROFILE=learning4 terraform destroy` |

---

## 8. Privacy-Sensitive Inspection (TLS 1.3, ECH, ESNI)

### The Challenge

With TLS 1.3 + Encrypted Client Hello (ECH) + ESNI, traditional visibility disappears:
- **TLS 1.3:** handshake encrypted after ServerHello — no passive eavesdropping
- **ECH:** SNI is hidden inside an encrypted outer extension — NFW cannot read it
- **ESNI (deprecated, replaced by ECH):** same effect — destination hostname invisible
- **Result:** >90% of traffic is opaque if you rely only on SNI

### Our Layered Approach: Privacy-Preserving Visibility

```
┌─────────────────────────────────────────────────────────────────────┐
│            PRIVACY-PRESERVING INSPECTION STACK                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Layer 5 — CONSENT-BASED DECRYPTION (managed devices only)          │
│  ├─ TLS MITM via NFW (CA pushed by MDM/Aruba to MANAGED devices)   │
│  ├─ Full L7 visibility: HTTP host, URL, UA, content                │
│  └─ NOT applied to: BYOD, guest, IoT (privacy compliance)          │
│                                                                     │
│  Layer 4 — DNS-LEVEL VISIBILITY (all devices, no decryption)        │
│  ├─ Route 53 Resolver DNS Firewall — log ALL DNS queries            │
│  ├─ Block malicious domains BEFORE connection starts                │
│  ├─ Even with ECH, device must resolve DNS first → visible          │
│  └─ Privacy-safe: domain-level only, no payload                    │
│                                                                     │
│  Layer 3 — METADATA + BEHAVIORAL (zero decryption)                  │
│  ├─ IP reputation (GuardDuty threat intel feeds)                   │
│  ├─ Connection patterns: fan-out, beaconing, data exfil volumes    │
│  ├─ JA4 fingerprint (from unencrypted outer ClientHello)            │
│  ├─ Packet timing, sizes, entropy (ML classifiers)                 │
│  ├─ ALPN negotiation (h2, h3) — still visible in outer hello       │
│  └─ Destination IP → ASN/geo → app inference (Zoom=Zoom ASN)      │
│                                                                     │
│  Layer 2 — ENDPOINT TELEMETRY (Aruba-side, no AWS decryption)       │
│  ├─ Aruba AIE on-device: process name, app identity, user ID       │
│  ├─ Exported as structured metadata alongside flow                 │
│  └─ Correlate with AWS network data via timestamp + 5-tuple        │
│                                                                     │
│  Layer 1 — SELECTIVE DECRYPTION (compliance-scoped)                 │
│  ├─ Decrypt ONLY categories: uncategorized, newly-registered,      │
│  │   high-risk, or policy-flagged domains                          │
│  ├─ Skip known-good: banking, healthcare, government               │
│  └─ NFW TLS scope config supports include/exclude CIDRs + domains  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### ECH-Specific Mitigations

| Technique | How it works | Privacy impact |
|---|---|---|
| **DNS visibility** | ECH requires DNS to fetch the ECH config (HTTPS RR). Logging DNS reveals the target domain BEFORE ECH hides it. | Low — domain only |
| **Block QUIC + force TCP** | Already doing this (sid:1). Forces inspectable path. | None |
| **Block ECH outer extension** | NFW Suricata rule: `drop tls any any -> any any (tls.extensions; content:\|ff0d\|; msg:"Block ECH"; sid:100;)` | Aggressive — forces TLS 1.3 fallback without ECH |
| **IP/ASN classification** | Map destination IPs to known services. ECH hides hostname but not IP. | None |
| **Endpoint attestation** | Only allow traffic from devices that report app identity (Aruba AIE). Unattested = blocked or quarantined. | Shifts trust to endpoint |

### Privacy Compliance Matrix

| Scenario | Decryption? | Visibility | Compliance |
|---|---|---|---|
| Corporate-managed device | ✅ Full TLS MITM | Complete L7 | Consent via employment policy |
| BYOD (personal device) | ❌ No decryption | DNS + metadata + behavioral | GDPR/CCPA compliant |
| Guest network | ❌ No decryption | DNS filtering only | Minimal data collection |
| Regulated traffic (banking) | ❌ Excluded from MITM | IP/port/volume only | PCI-DSS / HIPAA safe |

**Key message:** You don't need to decrypt everything. The stack gives security visibility
at every layer — decryption is the strongest tool but only one of five layers.

---

## 9. AI-Aware Architecture — Agentic Security

### 9.1 Where AI Agents Fit

```
┌─────────────────────────────────────────────────────────────────────┐
│                    AI-DRIVEN SECURITY LOOP                           │
│                                                                     │
│   ┌─────────┐     ┌──────────────┐     ┌───────────────┐          │
│   │ DETECT  │────►│   ANALYZE    │────►│    RESPOND    │          │
│   │         │     │              │     │               │          │
│   │ NFW     │     │ Bedrock      │     │ Step Functions│          │
│   │ GuardDuty│    │ Agent        │     │ + SSM         │          │
│   │ Security│     │ (Claude)     │     │ Automation    │          │
│   │ Hub     │     │              │     │               │          │
│   └────┬────┘     └──────┬───────┘     └───────┬───────┘          │
│        │                 │                      │                  │
│        │    ┌────────────▼─────────────┐        │                  │
│        │    │     MCP TOOL LAYER       │        │                  │
│        │    │                          │        │                  │
│        │    │  • CloudWatch Logs query │        │                  │
│        │    │  • Athena (S3 lake)      │◄───────┘                  │
│        │    │  • GuardDuty findings    │                           │
│        │    │  • NFW rule management   │                           │
│        │    │  • Security Hub ASFF     │                           │
│        │    │  • WAF/NACL updates      │                           │
│        │    │  • Aruba Central API     │ ← Bidirectional           │
│        │    └──────────────────────────┘                           │
│        │                                                           │
│        ▼                                                           │
│   EventBridge ── triggers agent on finding/alarm                   │
└─────────────────────────────────────────────────────────────────────┘
```

### 9.2 Bedrock Agent + MCP Implementation

**Amazon Bedrock Agents** with MCP (Model Context Protocol) servers provide:

| Capability | Implementation |
|---|---|
| **Automated triage** | Agent receives Security Hub finding → queries NFW logs + GuardDuty → determines severity |
| **Root cause analysis** | Agent correlates across data sources: NFW alert → DNS query → flow pattern → threat intel |
| **Dynamic rule creation** | Agent writes Suricata rule → validates → deploys via NFW API (human-in-the-loop optional) |
| **Cross-platform correlation** | MCP server connects to Aruba Central API — correlate AWS network events with device identity |
| **Natural language SOC queries** | "Show me all TLS connections to newly-registered domains from unmanaged devices in the last hour" |
| **Adaptive policy** | Agent monitors false-positive rate → adjusts rule thresholds → reports to SOC |

**MCP Server Architecture:**
```
Bedrock Agent (Claude Sonnet)
    │
    ├── MCP Server: aws-security
    │   ├── tool: query_nfw_logs(timerange, filter)
    │   ├── tool: query_guardduty_findings(severity, type)
    │   ├── tool: update_nfw_rules(rule_group, rule_string)
    │   ├── tool: query_athena(sql)  ← S3 lake
    │   └── tool: create_security_hub_finding(asff)
    │
    ├── MCP Server: aruba-central
    │   ├── tool: get_device_identity(ip, mac)
    │   ├── tool: get_device_posture(device_id)
    │   ├── tool: quarantine_device(device_id)
    │   └── tool: push_policy(device_group, policy)
    │
    └── MCP Server: threat-intel
        ├── tool: lookup_ip_reputation(ip)
        ├── tool: lookup_domain_age(domain)
        └── tool: check_ioc(indicator)
```

### 9.3 Agentic Use Cases for Aruba

| Use Case | Trigger | Agent Action | Outcome |
|---|---|---|---|
| **Unknown app detected** | NFW sees unclassified SNI pattern | Query threat intel → classify → add Suricata rule or block | Auto-expanding app signatures |
| **Data exfiltration** | Flow log: device uploads >100MB to uncategorized domain | Correlate with Aruba device identity → alert SOC → optional quarantine | MTTR < 5 min |
| **ECH evasion attempt** | DNS log shows HTTPS RR fetch for suspicious domain | Block at DNS level + add IP to deny list + notify | Proactive defense |
| **Anomalous behavior** | ML model flags torrent-like pattern | Agent investigates: is it legit backup? P2P? → decide action | Reduce false positives |
| **New CVE published** | Threat intel feed update | Agent generates Suricata signature → test → deploy to NFW | Zero-day protection in minutes |

---

## 10. End-to-End Orchestrated Incident Response

### 10.1 Beyond Suricata — Full Security Stack

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 END-TO-END SECURITY ORCHESTRATION                            │
│                                                                             │
│  PREVENT          DETECT              INVESTIGATE         RESPOND           │
│  ────────         ──────              ───────────         ───────           │
│                                                                             │
│  NFW (DPI/IPS)    GuardDuty           Bedrock Agent       Step Functions    │
│  WAF              Security Hub        (autonomous RCA)    SSM Automation    │
│  Shield           NFW alerts                              Lambda            │
│  DNS Firewall     VPC Flow Logs       Detective           Aruba Central     │
│  NACL/SG          CloudTrail          (graph analysis)    (quarantine)      │
│                   Macie (DLP)                                               │
│                   Inspector                                                 │
│                                                                             │
│  ┌────────────── EventBridge (central event bus) ────────────────────┐     │
│  │                                                                    │     │
│  │  Finding published → Agent triages → Escalates or auto-remediates │     │
│  │                                                                    │     │
│  └────────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  ┌──────────── AWS Security Incident Response ───────────────────────┐     │
│  │  • Auto-triage (filters >99% noise)                                │     │
│  │  • Agentic AI investigation                                        │     │
│  │  • 24/7 AWS security engineers (optional)                         │     │
│  │  • Case management + Jira/Slack/ServiceNow integration            │     │
│  └────────────────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 10.2 Incident Response Workflow

```
     DEVICE            AWS INSPECTION          AI LAYER              ACTION
     ──────            ──────────────          ────────              ──────

  1. User browses   →  NFW decrypts        
     malicious site     detects C2 beacon   →  GuardDuty finding  →  EventBridge
                                                                          │
                                                                          ▼
                                               Bedrock Agent         ┌─────────┐
                                               receives finding      │ TRIAGE  │
                                               queries:              │         │
                                               • NFW logs (context)  │ Sev?    │
                                               • Device identity     │ Scope?  │
                                               • Threat intel        │ Real?   │
                                               • Historical S3 data  └────┬────┘
                                                                          │
                                            ┌─── LOW ───┐    ┌─── HIGH ───┤
                                            ▼            │    ▼            │
                                       Log + monitor     │  Auto-respond:  │
                                       (no action)       │  • Block IP/domain│
                                                         │    in NFW rules  │
                                                         │  • Quarantine    │
                                                         │    device (Aruba)│
                                                         │  • Isolate VPC   │
                                                         │    (NACL update) │
                                                         │  • Create case   │
                                                         │    (Security IR) │
                                                         └─────────────────┘

  2. SOC reviews     ←─── Notification (Slack/PagerDuty/Jira) ───────────┘
     validates
     closes or
     escalates
```

### 10.3 AWS Services Involved (not just Suricata)

| Layer | Service | Role |
|---|---|---|
| **Network DPI** | AWS Network Firewall | TLS decrypt, Suricata IPS, app detection |
| **Web protection** | AWS WAF | L7 app-layer rules (rate limiting, bot control, SQLi/XSS) |
| **DDoS** | AWS Shield Advanced | Volumetric + application-layer DDoS mitigation |
| **DNS security** | Route 53 Resolver DNS Firewall | Block malicious domains, log all queries |
| **Threat detection** | Amazon GuardDuty | ML-based anomaly detection across VPC flows, DNS, CloudTrail |
| **Posture management** | AWS Security Hub | Aggregates findings, compliance checks (CIS, PCI) |
| **Data protection** | Amazon Macie | Detect PII/sensitive data in S3 lake |
| **Vulnerability** | Amazon Inspector | CVE scanning on containers/EC2 |
| **Investigation** | Amazon Detective | Graph-based entity analysis (IP, user, resource relationships) |
| **Incident response** | AWS Security Incident Response | Auto-triage, AI investigation, case management |
| **Automation** | AWS Step Functions + SSM | Orchestrate remediation workflows |
| **AI reasoning** | Amazon Bedrock Agents | Natural language investigation, rule generation, correlation |
| **Data lake** | Security Lake (OCSF) | Normalized log aggregation for cross-service queries |

### 10.4 The "Modern Spin" — What Makes This Different

| Traditional SOC | This Architecture |
|---|---|
| Alert → human reads log → decides | Alert → AI agent reads all logs → recommends/acts |
| Static rules, manual updates | Agent generates + deploys rules from threat intel |
| Siloed tools (firewall, EDR, SIEM) | MCP connects all tools into one agent context |
| IP-based policies | Intent-based: "inspect AI apps" → agent figures out which IPs/SNIs |
| Hours to respond | Seconds (EventBridge → Agent → automation) |
| Single-vendor locked | Open MCP protocol → Aruba + AWS + any tool |
| Reactive only | Predictive: ML behavioral models + agent pre-positions rules |

---

## 11. Implementation Phases

| Phase | Timeline | Scope |
|---|---|---|
| **Phase 1 (NOW)** | Complete | NFW + TLS decrypt + app detection + UI + S3 lake |
| **Phase 2** | Q3 2026 | DNS Firewall + GuardDuty + Security Hub integration |
| **Phase 3** | Q3 2026 | Bedrock Agent with MCP (NFW + Aruba Central tools) |
| **Phase 4** | Q4 2026 | Full incident response loop (Step Functions + auto-remediation) |
| **Phase 5** | Q4 2026 | 3rd-party appliance (GWLB) + inbound inspection |

---
