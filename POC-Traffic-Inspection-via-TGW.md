# POC: Outbound Traffic Inspection via AWS Transit Gateway

**Customer:** Aruba / HPE  **Scope:** Outbound (device → app), bidirectional-ready  **Date:** 2026-05-31

---

## 1. Architecture (centralized inspection VPC)

```
Aruba edge / gateway ──VPN/DX──► Spoke VPC ──► Transit Gateway
                                                    │ (appliance mode ON)
                                                    ▼
                                            Inspection VPC
                                  GWLBE ─► GWLB ─► inspection fleet
                                                    │
                                  (a) AWS Network Firewall endpoint  ← native TLS inspection
                                  (b) HPE SSE / 3rd-party appliance behind GWLB (GENEVE)
                                                    │
                                                    ▼
                                      TGW ─► egress VPC (NAT GW/IGW) ─► Internet/App
```

- **TGW appliance mode is mandatory** on the inspection VPC attachment. It uses a 4-tuple hash to keep request + response on the same appliance/AZ (flow symmetry), which stateful inspection and TLS termination require.
- GWLB is L3, listens on all ports, and forwards traffic to the appliance fleet using **GENEVE on UDP 6081**. It scales the fleet and does health checks; it does **not** itself decrypt or inspect.
- Two valid inspection engines: **(a) AWS Network Firewall** (native, managed, does TLS decryption) or **(b) a 3rd-party/HPE SSE appliance** behind GWLB. They can also be combined.

---

## 2. Can we terminate TLS to read the traffic? — Yes (with conditions)

AWS Network Firewall supports **TLS inspection** = a transparent forward proxy (MITM):

1. Client TLS is **terminated** at the firewall, traffic **decrypted**, inspected by the Suricata stateful engine (deep packet inspection on the cleartext), then **re-encrypted with TLS 1.3** to the destination.
2. **Outbound** requires a **CA certificate imported into ACM** (`CertificateAuthorityArn`); the firewall mints leaf certs on the fly. **This CA must be trusted/installed on the end devices** (Aruba can push it) — otherwise clients get cert errors.
3. **Inbound** requires an imported **server certificate per domain**.

**Supported:** TLS 1.1/1.2/1.3, HTTPS + other TCP TLS protocols (SMTPS, POP3s), decrypted **HTTP/2** inspection.

**Will be DROPPED / NOT supported (flag to customer):**
| Item | Status | Action |
|---|---|---|
| **Encrypted Client Hello (ECH) / Encrypted SNI** | ❌ Not supported | Customer's workflow lists "decrypt encrypted Client Hello" — **AWS cannot do this.** Connection is reset when no SNI is found. |
| **QUIC / HTTP3 (UDP 443)** | ❌ Not supported | Must **block QUIC** with a firewall rule to force apps (Chrome, Google, Meta) to fall back to TCP/TLS, else they bypass inspection. |
| StartTLS, TLS 1.0/SSL | ❌ | Excluded from scope. |
| Non-TLS traffic inside TLS scope | Dropped | Scope carefully. |
| TLS with no SNI / SNI≠server cert | Dropped | Expected. |
| Traffic terminated at an upstream ALB | Cannot inspect | N/A for this design. |

---

## 3. How do we inspect mTLS (mutual TLS) customer traffic? — The honest answer

**A transparent proxy cannot complete mutual-TLS to an origin that requires a client certificate.** Network Firewall's TLS inspection config only accepts a **CA cert (outbound)** or **server certs (inbound)** — there is **no provision to present a client certificate** to the upstream server. Because the firewall does not hold the client's private key, the server's client-auth handshake fails. This is an architectural reality of *any* TLS-terminating proxy, not an AWS-specific gap.

Practical options for mTLS flows:
1. **Bypass (recommend for POC):** Exclude known mTLS destinations from the TLS inspection scope. You still get **5-tuple + TLS.SNI** visibility (SNI is readable without decryption), just not the payload.
2. **Re-originate mTLS at the appliance:** Provision the appliance/SSE node with the client identity (cert + key) so it terminates the device side and opens a *new* mTLS session to the origin. Requires key custody and per-destination config — heavy operational overhead, only for a small set of sanctioned apps.
3. **Inspect at the device/SSE before the second leg's mTLS is applied** (Aruba-side), then send already-cleartext or single-TLS traffic to AWS.

> Note: mTLS *between Aruba SSE and Network Firewall* (their own components, as in their doc) is fine — that's their control channel, not the customer's app traffic.

---

## 4. What fields are visible in the inspection VPC?

### Through GWLB (GENEVE)
GWLB **encapsulates and forwards the entire original packet** (L3/L4 headers + full payload) plus TLV metadata to the appliance. So the **appliance — not GWLB — sees everything on the wire**:
- Without decryption: full IP headers, TCP/UDP, and the **TLS handshake (incl. SNI, JA3/JA4 fingerprints)**, but payload stays ciphertext.
- With TLS termination (NFW or appliance): full cleartext L7.
- GENEVE TLV metadata identifies the **source GWLBE / consumer VPC**, which is useful for attribution (see §6).

### VPC Flow Logs — yes, available in the inspection VPC
Enable on the GWLBE ENIs / appliance ENIs / subnet / VPC. **Metadata only — no payload, no SNI, no domain/URL.** Key fields:
- 5-tuple: `srcaddr`, `dstaddr`, `srcport`, `dstport`, `protocol`
- `packets`, `bytes`, `start`, `end`, `action` (ACCEPT/REJECT), `tcp-flags`
- `vpc-id`, `subnet-id`, `instance-id`, `interface-id`, `az-id`, `region`, `type`
- **`pkt-srcaddr` / `pkt-dstaddr`** — the *original* client/app IPs (critical: behind TGW/GWLB the `srcaddr` is the intermediate; these give the real endpoints)
- `flow-direction`, `traffic-path`, `pkt-src-aws-service`/`pkt-dst-aws-service`, `encryption-status`

### Network Firewall logs (the real application-identity source) — Suricata EVE JSON
- **TLS metadata (even without full decrypt):** `tls.sni`, `tls.version`, JA3/JA4
- **Decrypted L7:** `http.hostname`/`:authority`, `url`, `http_method`, `user-agent`, `request_headers`, `app_proto` (http2/tls)
- **`aws_category`** — URL/domain category (e.g. `["Search Engines and Portals"]`)
- `verdict`/`action`, `revocation_check`, and `tls_inspected: true` flag
- `pkt_src: "geneve encapsulation"` is shown when the firewall sits behind GWLB

---

## 5. What exactly can AWS see — summary table

| Layer | Source | Sees |
|---|---|---|
| L3/L4 + volume | VPC Flow Logs | IPs, ports, protocol, bytes/packets, original IPs, action. **No app identity.** |
| TLS metadata (no decrypt) | NFW / appliance | SNI, TLS version, JA3/JA4 → destination/app *hint* |
| Full L7 (decrypt) | NFW TLS inspection | Host/URL/method/headers/user-agent, domain category, payload patterns |
| mTLS to client-cert origins | — | 5-tuple + SNI only (payload not decryptable transparently) |
| ECH / QUIC | — | Nothing useful (block QUIC; ECH unsupported) |

---

## 6. Profiling multiple apps over one TGW attachment

A single TGW attachment carries many apps mixed together — the attachment itself does **not** separate them. Layer these signals:

1. **L7 identity (best):** NFW `tls.sni` / `http.hostname` / `url` / `aws_category` → map to app names (Salesforce, M365/Teams, etc.). Drives "inspect AI apps, skip sanctioned apps" intent rules.
2. **Original endpoints:** `pkt-srcaddr` / `pkt-dstaddr` in flow logs survive the TGW/GWLB hops → who talked to what.
3. **GENEVE TLV metadata:** identifies the source GWLBE/consumer VPC for per-tenant/per-site attribution over a shared appliance fleet.
4. **Topology segmentation:** per-app/per-tenant spoke VPC or subnet → filter by `vpc-id`/`subnet-id`; optionally per-app TGW route tables.

Flow logs **alone** profile only by IP/port + volume. App-level profiling (the customer's AIE "application identity") needs the **NFW SNI/domain/HTTP layer** (or decryption).

---

## 7. AI-based detection — what's technically feasible

**On decrypted Network Firewall logs (rich):**
- Application classification & **shadow-IT / unsanctioned-app detection** (SNI/host/category/JA3-JA4)
- DLP pattern matching on cleartext payload
- **C2 / beaconing**, **DGA domain** detection, malicious URL/category, TLS-fingerprint (JA3/JA4) anomaly

**On VPC Flow Logs (metadata only — behavioral/statistical):**
- Volumetric & exfil-by-volume anomalies, beaconing periodicity, port scans, lateral movement, new/unusual peer & geo anomalies

**AWS-native building blocks:**
- **GuardDuty** — managed ML over VPC Flow Logs + DNS + CloudTrail (C2, crypto-mining, anomalous behavior). No payload visibility.
- **Security Lake (OCSF) + SageMaker** — custom models on NFW logs (app classification, fingerprinting).
- **Bedrock** — triage, summarization, natural-language SOC queries over the inspection logs; feed unified app ID back to Aruba Central.

---

## 8. POC scope recommendation

1. Outbound only; one or two spoke VPCs simulating Aruba edge egress.
2. Centralized inspection VPC: TGW (appliance mode) → GWLBE → **AWS Network Firewall** with outbound TLS inspection (ACM CA pushed to test devices).
3. Block QUIC; exclude known mTLS destinations from TLS scope (SNI-only visibility there).
4. Logs: NFW alert/flow/TLS logs + VPC Flow Logs (custom format incl. `pkt-srcaddr`/`pkt-dstaddr`) → S3/Security Lake.
5. Detection: GuardDuty on flow/DNS; SNI/host-based app profiling + a Bedrock summarization layer; feed app-ID telemetry back to Aruba Central.

**Corrections to align with AWS reality:** ECH cannot be decrypted; QUIC must be blocked, not inspected; GWLB forwards packets (the appliance inspects); transparent mTLS interception to client-cert origins is not possible.
