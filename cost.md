# Cost Analysis — TrafInspector

## POC Observed Data (us-east-2, 2-AZ)

**Traffic inspected (estimate from NFW flow logs):**
- Test sessions: ~50-100 MB per `nfw-test.sh` run (curl requests + responses)
- Background VPN browsing: ~500 MB-1 GB/session
- Total over ~5 days of POC: ~5-10 GB inspected
- Connections logged: ~6000 per ingest cycle (24h window)

**Current monthly run rate: ~$1,450/mo (fixed) + negligible variable at POC volume.**

---

## Fixed Costs (always-on, regardless of volume)

| Component | $/mo (2-AZ, us-east-2) | Notes |
|---|---|---|
| NFW endpoints (2 AZ × $0.395/hr) | $568.80 | Scales with AZ count, not traffic |
| NFW TLS Inspection (2 AZ × $0.489/hr) | $704.16 | No per-GB charge for TLS |
| TGW attachments (2 × $0.05/hr) | $72.00 | Spoke + inspection |
| Client VPN endpoint association | $72.00 | Per-subnet association |
| GWLB (scaffold, idle) | $9.00 | $0.0125/hr |
| NAT Gateway (2 × $0.045/hr) | $64.80 | Hourly only (data via NFW) |
| DynamoDB (on-demand) | ~$5 | ~1M writes/reads/month at POC |
| S3 lake storage | ~$1 | < 1 GB stored |
| Lambdas (ingest + classifier + query + admin) | ~$3 | ~300K invocations/mo |
| Bedrock (Sonnet classifier) | ~$5 | ~15 items × 288 runs × $0.003/1K tokens |
| CloudWatch Logs (ingest + storage) | ~$10 | ~2 GB/mo at POC volume |
| CloudFront + API Gateway | ~$1 | Minimal requests |
| SNS | ~$0 | < 1000 notifications |
| **FIXED TOTAL** | **≈ $1,516/mo (~$2.10/hr)** | |

---

## Variable Costs (per-GB inspected)

| Component | $/GB | Notes |
|---|---|---|
| NFW data processing | $0.065 | Per GB through firewall |
| TGW data processing | $0.02 | Per GB through TGW (each direction) |
| TGW cross-AZ (appliance mode) | $0.02 | Return path |
| NAT Gateway data processing | $0.00 | Waived when chained with NFW |
| **VARIABLE TOTAL** | **$0.105/GB** | |

**TLS inspection adds NO per-GB charge** — it's hourly only. This is a major cost advantage at scale.

---

## Extrapolation: 100 TB/day Inspected

| Item | Calculation | $/mo |
|---|---|---|
| **Fixed (NFW + TGW + VPN + infra)** | Same as above | $1,516 |
| **NFW data processing** | 100 TB/day × 30 days × $0.065/GB | $195,000 |
| **TGW data processing** | 100 TB/day × 30 days × $0.04/GB | $120,000 |
| **CloudWatch Logs** | ~50 GB/day logs × 30 × $0.50/GB ingest | $750 |
| **S3 lake storage** | ~100 GB/day × 30 × $0.023/GB | $69 |
| **DynamoDB** | ~50M writes/mo × $1.25/M | $63 |
| **Bedrock classifier** | ~1000 new destinations/day × $0.01 | $9 |
| **TOTAL at 100 TB/day** | | **≈ $317,400/mo** |
| **Blended $/GB** | $317,400 / (100,000 GB × 30) | **$0.106/GB** |

**Key insight:** At 100 TB/day, variable cost dominates. Fixed costs become negligible (~0.5% of total).

---

## Scaling Options at 100 TB/day

100 TB/day = ~1.16 Gbps average (8.3 Gbps peak at 70% utilization).
**One 2-AZ NFW deployment handles this** (100 Gbps per endpoint = 200 Gbps capacity).

| Scale | Architecture | Capacity |
|---|---|---|
| < 200 Gbps (≈ 17 PB/day peak) | Current 2-AZ | ✅ No changes |
| 200-300 Gbps | Add 3rd AZ | 300 Gbps |
| 300 Gbps - 1 Tbps | Multiple NFW firewalls | Parallel inspection VPCs |
| 1+ Tbps | Multi-region | Regional NFW deployments |

---

## Cost Comparison: Inspect vs Don't Inspect

| Approach | $/GB | What you get |
|---|---|---|
| No inspection (raw flow logs only) | ~$0.00 | 5-tuple, no app identity, no DPI |
| NFW inspection (current) | $0.105 | Full L7 visibility, TLS decrypt, app detection |
| NFW + 3rd-party (Palo Alto via GWLB) | ~$0.16 | Add App-ID, User-ID, WildFire, DLP |
| Cloud proxy (Zscaler/Netskope SaaS) | ~$0.20-0.40 | Managed, but data leaves your VPC |

**NFW is the cheapest inline inspection** — TLS decryption is free per-GB, and managed rules are free.

---

## AI Classification Cost (separate from inspection)

| Phase | Bedrock calls/day | $/day | $/mo |
|---|---|---|---|
| Cold start (empty cache) | ~100 | $0.50 | $15 |
| Warm (cache populated) | ~10 | $0.05 | $1.50 |
| Steady state (100 TB/day) | ~50 new destinations | $0.25 | $7.50 |

AI classification cost is **independent of volume** — it scales with unique destinations, not total bytes. 100 TB/day from 10,000 devices still hits the same ~1000 unique destinations.

---

## Cost Optimization Levers

1. **Selective inspection** — only decrypt/inspect categories that matter (skip known-good CDNs)
2. **Single AZ** — cuts NFW fixed by 50% (loses HA)
3. **Reduce TLS inspection scope** — inspect only uncategorized/risky domains
4. **Reserved capacity** — NFW doesn't offer RI, but TGW has none either; only savings are volume
5. **Regional placement** — inspect locally to avoid cross-region data transfer ($0.02/GB)
